#!/usr/bin/env python3
# Copyright (c) 2026 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Ensure MWEB blocks are cached and fast-announced only after connection."""

import copy
import time

from test_framework.ltc_util import setup_mweb_chain
from test_framework.messages import (
    CBlock,
    CInv,
    FromHex,
    MSG_BLOCK,
    MSG_CMPCT_BLOCK,
    MSG_MWEB_BLOCK,
    msg_block,
    msg_getdata,
    msg_inv,
    msg_sendcmpct,
    NODE_MWEB,
    NODE_NETWORK,
    NODE_WITNESS,
)
from test_framework.p2p import P2PDataStore, P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BlockListener(P2PInterface):
    def __init__(self):
        super().__init__()
        self.blocks = []
        self.cmpctblocks = []

    def on_block(self, message):
        self.blocks.append(message.block)

    def on_cmpctblock(self, message):
        self.cmpctblocks.append(message.header_and_shortids)


def swap_commitments(block):
    """Create a same-hash MWEB body that fails UTXO-dependent validation."""
    mutated = copy.deepcopy(block)
    inputs = mutated.mweb_block.body.inputs
    assert_equal(len(inputs), 2)
    assert inputs[0].commitment != inputs[1].commitment
    inputs[0].commitment, inputs[1].commitment = (
        inputs[1].commitment,
        inputs[0].commitment,
    )
    for mweb_input in inputs:
        mweb_input.rehash()
    mutated.rehash()
    assert_equal(mutated.sha256, block.sha256)
    return mutated


def input_commitments(block):
    return [mweb_input.commitment for mweb_input in block.mweb_block.body.inputs]


class MWEBNewPoWValidBlockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [
            ['-whitelist=noban@127.0.0.1'],
            ['-whitelist=noban@127.0.0.1'],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def fund_two_spenders(self, source):
        source.createwallet(wallet_name="funder")
        source.createwallet(wallet_name="spender0")
        source.createwallet(wallet_name="spender1")
        miner = source.get_wallet_rpc(self.default_wallet_name)
        funder = source.get_wallet_rpc("funder")
        spender0 = source.get_wallet_rpc("spender0")
        spender1 = source.get_wallet_rpc("spender1")

        miner.sendtoaddress(funder.getnewaddress(address_type="mweb"), 12)
        source.generate(1)
        funder.sendtoaddress(spender0.getnewaddress(address_type="mweb"), 5)
        source.generate(1)
        funder.sendtoaddress(spender1.getnewaddress(address_type="mweb"), 5)
        source.generate(1)
        return spender0, spender1

    def mine_block_with_two_spends(self, source, spender0, spender1):
        spender0.sendtoaddress(spender0.getnewaddress(address_type="mweb"), 2)
        spender1.sendtoaddress(spender1.getnewaddress(address_type="mweb"), 2)
        block_hash = source.generate(1)[0]
        block = FromHex(CBlock(), source.getblock(block_hash, 0))
        block.rehash()
        assert_equal(block.hash, block_hash)
        return block

    def run_test(self):
        source, victim = self.nodes

        self.log.info("Set up and synchronize an MWEB chain")
        setup_mweb_chain(source)
        self.sync_blocks()
        spender0, spender1 = self.fund_two_spenders(source)
        self.sync_blocks()
        self.disconnect_nodes(0, 1)

        # Telling the victim we have its current tip makes this connection
        # eligible for compact-block fast announcements of the next block.
        listener = victim.add_p2p_connection(
            BlockListener(),
            services=NODE_NETWORK | NODE_WITNESS | NODE_MWEB,
        )
        listener.send_and_ping(msg_sendcmpct(announce=True, version=3))
        victim_tip = victim.getbestblockhash()
        listener.send_and_ping(msg_inv([CInv(MSG_BLOCK, int(victim_tip, 16))]))
        sender = victim.add_p2p_connection(P2PDataStore())

        self.log.info("Reject a same-hash MWEB mutation without announcing it")
        valid_block = self.mine_block_with_two_spends(source, spender0, spender1)
        mutated_block = swap_commitments(valid_block)
        with victim.assert_debug_log(expected_msgs=["mweb-connect-failed"], timeout=10):
            sender.send_and_ping(msg_block(mutated_block))
        assert_equal(victim.getbestblockhash(), victim_tip)
        time.sleep(5)
        assert_equal(len(listener.cmpctblocks), 0)

        self.log.info("Connect and fast-announce the honest same-hash block")
        sender.send_and_ping(msg_block(valid_block))
        self.wait_until(lambda: victim.getbestblockhash() == valid_block.hash, timeout=30)
        self.wait_until(lambda: len(listener.cmpctblocks) == 1, timeout=10)
        announced = listener.cmpctblocks[0]
        announced.header.rehash()
        assert_equal(announced.header.sha256, valid_block.sha256)
        assert_equal(input_commitments(announced), input_commitments(valid_block))

        self.log.info("Serve the honest body from both recent-block caches")
        listener.send_message(msg_getdata([
            CInv(MSG_CMPCT_BLOCK, valid_block.sha256),
            CInv(MSG_MWEB_BLOCK, valid_block.sha256),
        ]))
        self.wait_until(lambda: len(listener.cmpctblocks) == 2, timeout=10)
        self.wait_until(lambda: len(listener.blocks) == 1, timeout=10)
        assert_equal(input_commitments(listener.cmpctblocks[1]), input_commitments(valid_block))
        assert_equal(input_commitments(listener.blocks[0]), input_commitments(valid_block))

        self.log.info("Apply the same ordering to the submitblock path")
        valid_block2 = self.mine_block_with_two_spends(source, spender0, spender1)
        assert_equal(valid_block2.hashPrevBlock, valid_block.sha256)
        mutated_block2 = swap_commitments(valid_block2)
        with victim.assert_debug_log(expected_msgs=["mweb-connect-failed"], timeout=10):
            victim.submitblock(mutated_block2.serialize().hex())
        assert_equal(victim.getbestblockhash(), valid_block.hash)
        time.sleep(5)
        assert_equal(len(listener.cmpctblocks), 2)

        victim.submitblock(valid_block2.serialize().hex())
        self.wait_until(lambda: victim.getbestblockhash() == valid_block2.hash, timeout=30)
        self.wait_until(lambda: len(listener.cmpctblocks) == 3, timeout=10)
        announced2 = listener.cmpctblocks[2]
        announced2.header.rehash()
        assert_equal(announced2.header.sha256, valid_block2.sha256)
        assert_equal(input_commitments(announced2), input_commitments(valid_block2))


if __name__ == '__main__':
    MWEBNewPoWValidBlockTest().main()
