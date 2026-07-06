#!/usr/bin/env python3
# Copyright (c) 2019-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test basic signet functionality"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class SignetBasicTest(BitcoinTestFramework):
    def set_test_params(self):
        self.chain = "signet"
        self.num_nodes = 6
        self.setup_clean_chain = True
        shared_args1 = ["-signetchallenge=51"]  # OP_TRUE
        shared_args2 = []  # default challenge
        # we use the exact same challenge except we do it as a 2-of-2, which means it should fail
        shared_args3 = ["-signetchallenge=522103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae"]

        self.extra_args = [
            shared_args1, shared_args1,
            shared_args2, shared_args2,
            shared_args3, shared_args3,
        ]

    def setup_network(self):
        self.setup_nodes()

        # Setup the three signets, which are incompatible with each other
        self.connect_nodes(0, 1)
        self.connect_nodes(2, 3)
        self.connect_nodes(4, 5)

    def run_test(self):
        self.log.info("basic tests using OP_TRUE challenge")

        self.log.info('getmininginfo')
        mining_info = self.nodes[0].getmininginfo()
        assert_equal(mining_info['blocks'], 0)
        assert_equal(mining_info['chain'], 'signet')
        assert 'currentblocktx' not in mining_info
        assert 'currentblockweight' not in mining_info
        assert_equal(mining_info['networkhashps'], Decimal('0'))
        assert_equal(mining_info['pooledtx'], 0)

        self.generate(self.nodes[0], 1, sync_fun=self.no_op)
        self.sync_blocks([self.nodes[0], self.nodes[1]])

        self.log.info("mined signet block check")
        assert_equal(self.nodes[0].getblockcount(), 1)
        assert_equal(self.nodes[1].getblockcount(), 1)

        block_hash = self.nodes[0].getblockhash(1)
        block = self.nodes[0].getblock(block_hash, 0)

        self.log.info("mined signet block check (incompatible solution)")

        assert_equal(self.nodes[4].submitblock(block), 'bad-signet-blksig')

        self.log.info("test that signet logs the network magic on node start")
        with self.nodes[0].assert_debug_log(["Signet derived magic (message start)"]):
            self.restart_node(0)


if __name__ == '__main__':
    SignetBasicTest().main()
