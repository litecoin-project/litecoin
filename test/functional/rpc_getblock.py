#!/usr/bin/env python3
# Copyright (c) 2021 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test getblock verbosity levels, in particular verbosity 3 (prevout/fee).

Covers the backport of Bitcoin Core PR #18354 adapted for MWEB. The MWEB
specific fee-omission behaviour (HogEx / peg-in transactions) is exercised
by the mweb_* functional tests; this test covers the canonical path.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_is_hex_string,
    assert_raises_rpc_error,
)


class GetBlockVerbosityTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.supports_cli = False

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Mine a chain and create a canonical spend")
        addr = node.getnewaddress()
        node.generatetoaddress(101, addr)
        txid = node.sendtoaddress(addr, 1.0)
        # Fee the wallet reports paying (negative), for cross-checking below.
        wallet_fee = -node.gettransaction(txid)["fee"]
        blockhash = node.generatetoaddress(1, addr)[0]

        block = node.getblock(blockhash, 2)
        assert txid in [t["txid"] for t in block["tx"]]

        self.log.info("verbosity 0 returns hex, and matches the boolean 'false' form")
        block_hex = node.getblock(blockhash, 0)
        assert_is_hex_string(block_hex)
        assert_equal(block_hex, node.getblock(blockhash, False))

        self.log.info("verbosity 1 lists txids, and matches the boolean 'true' form")
        block1 = node.getblock(blockhash, 1)
        assert all(isinstance(t, str) for t in block1["tx"])
        assert_equal(block1["tx"], node.getblock(blockhash, True)["tx"])

        self.log.info("verbosity 2 expands txs but has no fee/prevout")
        block2 = node.getblock(blockhash, 2)
        spend2 = [t for t in block2["tx"] if t["txid"] == txid][0]
        assert isinstance(spend2, dict)
        assert "fee" not in spend2
        assert "prevout" not in spend2["vin"][0]

        self.log.info("verbosity 3 adds fee and per-input prevout")
        block3 = node.getblock(blockhash, 3)
        spend3 = [t for t in block3["tx"] if t["txid"] == txid][0]
        coinbase3 = block3["tx"][0]

        # Fee is present, positive, internally consistent, and matches the wallet.
        assert "fee" in spend3
        assert_greater_than(spend3["fee"], 0)
        total_in = sum(vin["prevout"]["value"] for vin in spend3["vin"])
        total_out = sum(vout["value"] for vout in spend3["vout"])
        assert_equal(spend3["fee"], total_in - total_out)
        assert_equal(spend3["fee"], wallet_fee)

        # prevout shape.
        prevout = spend3["vin"][0]["prevout"]
        assert_equal(set(prevout.keys()), {"generated", "height", "value", "scriptPubKey"})
        assert_equal(prevout["generated"], True)  # spends a coinbase output
        assert_greater_than(prevout["height"], 0)
        assert isinstance(prevout["value"], Decimal)
        assert "scriptPubKey" in prevout

        # Coinbase carries neither fee nor prevout.
        assert "fee" not in coinbase3
        assert "coinbase" in coinbase3["vin"][0]
        assert "prevout" not in coinbase3["vin"][0]

        self.log.info("verbosity > 3 behaves like verbosity 3")
        block4 = node.getblock(blockhash, 4)
        spend4 = [t for t in block4["tx"] if t["txid"] == txid][0]
        assert "fee" in spend4
        assert "prevout" in spend4["vin"][0]

        self.log.info("verbosity 2 output is unchanged whether or not undo is read")
        # (Sanity: v2 must never gain fee/prevout regardless of verbosity 3 use.)
        block2_again = node.getblock(blockhash, 2)
        assert "fee" not in [t for t in block2_again["tx"] if t["txid"] == txid][0]

        self.log.info("Unknown block hash is rejected at verbosity 3")
        assert_raises_rpc_error(-5, "Block not found", node.getblock, "00" * 32, 3)


if __name__ == "__main__":
    GetBlockVerbosityTest().main()
