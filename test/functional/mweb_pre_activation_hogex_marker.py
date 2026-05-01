#!/usr/bin/env python3
# Copyright (c) 2026 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test pre-activation HogEx marker malleation is rejected as mutated data.

Before MWEB activation, a peer must not be able to send a block whose canonical
header and tx merkle root match an honest block, but whose witness/MWEB
serialization marks a non-final transaction as HogEx. That marker is not part of
the block hash, and accepting it would mark outputs after vout[0] as pegouts in
the UTXO set.
"""

import copy

from test_framework.blocktools import (
    create_block,
    create_coinbase,
    create_tx_with_script,
)
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
)
from test_framework.p2p import P2PDataStore
from test_framework.script import CScript, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class MWEBPreActivationHogExMarkerTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-whitelist=noban@127.0.0.1"], []]

    def setup_network(self):
        self.setup_nodes()

    def make_block(self, prev_hash, height, block_time, txlist=None):
        block = create_block(
            prev_hash,
            create_coinbase(height),
            block_time,
            txlist=txlist or [],
            version=0x20000000,
        )
        block.solve()
        return block

    def submit_to_all(self, block):
        block_hex = block.serialize().hex()
        for node in self.nodes:
            assert_equal(node.submitblock(block_hex), None)

    def run_test(self):
        victim = self.nodes[0]
        honest = self.nodes[1]

        self.log.info("Build a shared pre-activation chain with mature coinbases")
        tip_hash = int(victim.getbestblockhash(), 16)
        block_time = victim.getblock(victim.getbestblockhash())["time"] + 1
        blocks = []
        for height in range(1, 102):
            block = self.make_block(tip_hash, height, block_time)
            self.submit_to_all(block)
            blocks.append(block)
            tip_hash = block.sha256
            block_time += 1

        self.log.info("Create an honest parent with a spendable non-coinbase output")
        fund_tx = CTransaction()
        fund_tx.vin = [
            CTxIn(COutPoint(blocks[0].vtx[0].sha256, 0), b"", 0xffffffff)
        ]
        fund_tx.vout = [
            CTxOut(10 * COIN, CScript([OP_TRUE])),
            CTxOut(10 * COIN, CScript([OP_TRUE])),
        ]
        fund_tx.rehash()

        # Keep the marked transaction away from the final position so the block
        # does not need an attached MWEB body to serialize as an attacker block.
        filler_tx = create_tx_with_script(
            blocks[1].vtx[0],
            0,
            amount=1 * COIN,
            script_pub_key=CScript([OP_TRUE]),
        )

        honest_parent = self.make_block(
            tip_hash,
            102,
            block_time,
            txlist=[fund_tx, filler_tx],
        )

        poisoned_parent = copy.deepcopy(honest_parent)
        poisoned_parent.vtx[1].hogex = True
        poisoned_parent.vtx[1].rehash()

        assert_equal(poisoned_parent.vtx[1].sha256, honest_parent.vtx[1].sha256)
        assert_equal(poisoned_parent.hashMerkleRoot, honest_parent.hashMerkleRoot)
        assert_equal(poisoned_parent.sha256, honest_parent.sha256)
        assert poisoned_parent.serialize() != honest_parent.serialize()

        self.log.info("Create a child that spends vout[1] from the marked transaction")
        spend_tx = create_tx_with_script(
            fund_tx,
            1,
            amount=1 * COIN,
            script_pub_key=CScript([OP_TRUE]),
        )
        child = self.make_block(
            honest_parent.sha256,
            103,
            block_time + 1,
            txlist=[spend_tx],
        )

        self.log.info("Show the honest parent and child are accepted on an unpoisoned node")
        assert_equal(honest.submitblock(honest_parent.serialize().hex()), None)
        assert_equal(honest.submitblock(child.serialize().hex()), None)
        assert_equal(honest.getbestblockhash(), child.hash)

        self.log.info("Reject the same-hash poisoned parent from a peer")
        peer = victim.add_p2p_connection(P2PDataStore())
        peer.send_blocks_and_test(
            [poisoned_parent],
            victim,
            success=False,
            force_send=True,
            reject_reason="unexpected-mweb-data",
        )
        assert_equal(victim.getbestblockhash(), blocks[-1].hash)

        self.log.info(
            "Accept the honest same-hash parent and its child after rejecting the mutation"
        )
        assert_equal(victim.submitblock(honest_parent.serialize().hex()), None)
        assert_equal(victim.submitblock(child.serialize().hex()), None)
        assert_equal(victim.getbestblockhash(), child.hash)


if __name__ == "__main__":
    MWEBPreActivationHogExMarkerTest().main()
