#!/usr/bin/env python3
# Copyright (c) 2019-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test basic signet functionality for Litecoin's scrypt-based signet."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

CUSTOM_CHALLENGE = "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae"
CUSTOM_CHALLENGE_2_OF_2 = "522103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae"
DEFAULT_MAGIC = "54d26fbd"
CUSTOM_MAGIC = "0a03cf40"
CUSTOM_2_OF_2_MAGIC = "7f2df3ca"


class SignetBasicTest(BitcoinTestFramework):
    def set_test_params(self):
        self.chain = "signet"
        self.num_nodes = 6
        self.setup_clean_chain = True
        self.rpc_timeout = 240
        self.extra_args = [
            [],
            [],
            [f"-signetchallenge={CUSTOM_CHALLENGE}"],
            [f"-signetchallenge={CUSTOM_CHALLENGE}"],
            [f"-signetchallenge={CUSTOM_CHALLENGE_2_OF_2}"],
            [f"-signetchallenge={CUSTOM_CHALLENGE_2_OF_2}"],
        ]

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(1, 0)
        self.connect_nodes(3, 2)
        self.connect_nodes(5, 4)

    def assert_signet_magic(self, node, expected_magic):
        with self.nodes[node].assert_debug_log([f"Signet derived magic (message start): {expected_magic}"]):
            self.restart_node(node)

    def run_test(self):
        self.log.info("basic tests using OP_TRUE challenge")

        self.log.info("getmininginfo")
        mining_info = self.nodes[0].getmininginfo()
        assert_equal(mining_info["blocks"], 0)
        assert_equal(mining_info["chain"], "signet")
        assert "currentblocktx" not in mining_info
        assert "currentblockweight" not in mining_info
        assert_equal(mining_info["networkhashps"], Decimal("0"))
        assert_equal(mining_info["pooledtx"], 0)

        self.log.info("mine a block on the OP_TRUE signet and sync the matching peer")
        self.nodes[0].generate(1, maxtries=10000000)
        self.sync_blocks([self.nodes[0], self.nodes[1]])
        assert_equal(self.nodes[1].getblockcount(), 1)

        self.log.info("blocks from one signet challenge are rejected by other signets")
        block = self.nodes[0].getblock(self.nodes[0].getbestblockhash(), 0)
        assert_equal(self.nodes[2].submitblock(block), "bad-signet-blksig")
        assert_equal(self.nodes[2].getblockcount(), 0)
        assert_equal(self.nodes[4].submitblock(block), "bad-signet-blksig")
        assert_equal(self.nodes[4].getblockcount(), 0)

        self.log.info("test that signet logs the derived network magic on node start")
        self.assert_signet_magic(0, DEFAULT_MAGIC)
        self.assert_signet_magic(2, CUSTOM_MAGIC)
        self.assert_signet_magic(4, CUSTOM_2_OF_2_MAGIC)


if __name__ == "__main__":
    SignetBasicTest().main()
