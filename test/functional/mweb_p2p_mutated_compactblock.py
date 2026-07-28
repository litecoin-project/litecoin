#!/usr/bin/env python3
# Copyright (c) 2026 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Check that a compact block with a mutated MWEB body discourages its peer."""

import copy

from test_framework.ltc_util import setup_mweb_chain
from test_framework.messages import (
    BlockTransactions,
    CBlock,
    FromHex,
    HeaderAndShortIDs,
    msg_blocktxn,
    msg_cmpctblock,
    msg_sendcmpct,
    NODE_MWEB,
    NODE_NETWORK,
    NODE_WITNESS,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class CompactBlockPeer(P2PInterface):
    def __init__(self):
        super().__init__()
        self.block = None

    def on_getblocktxn(self, message):
        indexes = message.block_txn_request.to_absolute()
        response = msg_blocktxn()
        response.block_transactions = BlockTransactions(
            self.block.sha256,
            [self.block.vtx[index] for index in indexes],
        )
        self.send_message(response)

    def send_compact_block(self, block):
        self.block = block
        compact_block = HeaderAndShortIDs()
        compact_block.initialize_from_block(block, version=3)
        self.send_message(msg_cmpctblock(compact_block.to_p2p(), version=3))


class MWEBP2PMutatedCompactBlockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        source, victim = self.nodes

        self.log.info("Set up and synchronize an MWEB chain")
        setup_mweb_chain(source)
        self.sync_blocks()

        self.log.info("Create two independent MWEB spends for the mutated block")
        source.createwallet(wallet_name="funder")
        source.createwallet(wallet_name="spender0")
        source.createwallet(wallet_name="spender1")
        miner = source.get_wallet_rpc(self.default_wallet_name)
        funder = source.get_wallet_rpc("funder")
        spender0 = source.get_wallet_rpc("spender0")
        spender1 = source.get_wallet_rpc("spender1")

        funder_addr = funder.getnewaddress(address_type="mweb")
        miner.sendtoaddress(funder_addr, 12)
        source.generate(1)

        spender0_addr = spender0.getnewaddress(address_type="mweb")
        funder.sendtoaddress(spender0_addr, 5)
        source.generate(1)

        spender1_addr = spender1.getnewaddress(address_type="mweb")
        funder.sendtoaddress(spender1_addr, 5)
        source.generate(1)

        assert_equal(len(spender0.listunspent(addresses=[spender0_addr])), 1)
        assert_equal(len(spender1.listunspent(addresses=[spender1_addr])), 1)
        self.sync_blocks()
        self.disconnect_nodes(0, 1)

        peer = victim.add_p2p_connection(
            CompactBlockPeer(),
            services=NODE_NETWORK | NODE_WITNESS | NODE_MWEB,
        )
        peer.send_and_ping(msg_sendcmpct(announce=True, version=3))

        self.log.info("Accept a valid MWEB compact block")
        valid_hash = source.generate(1)[0]
        valid_block = FromHex(CBlock(), source.getblock(valid_hash, 0))
        valid_block.rehash()
        peer.send_compact_block(valid_block)
        self.wait_until(lambda: victim.getbestblockhash() == valid_hash, timeout=10)

        self.log.info("Mutate an MWEB compact block without changing its block hash")
        spender0.sendtoaddress(spender0.getnewaddress(address_type="mweb"), 2)
        spender1.sendtoaddress(spender1.getnewaddress(address_type="mweb"), 2)
        mutated_hash = source.generate(1)[0]
        valid_block = FromHex(CBlock(), source.getblock(mutated_hash, 0))
        valid_block.rehash()

        mutated_block = copy.deepcopy(valid_block)
        inputs = mutated_block.mweb_block.body.inputs
        assert_equal(len(inputs), 2)
        assert inputs[0].output_pubkey != inputs[1].output_pubkey
        inputs[0].output_pubkey, inputs[1].output_pubkey = (
            inputs[1].output_pubkey,
            inputs[0].output_pubkey,
        )
        for mweb_input in inputs:
            mweb_input.rehash()
        mutated_block.rehash()
        assert_equal(mutated_block.sha256, valid_block.sha256)

        with victim.assert_debug_log(expected_msgs=["bad-blk-mweb", "Misbehaving"], timeout=10):
            peer.send_compact_block(mutated_block)
            peer.wait_for_disconnect(timeout=10)

        assert_equal(victim.getbestblockhash(), valid_hash)


if __name__ == '__main__':
    MWEBP2PMutatedCompactBlockTest().main()
