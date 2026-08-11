#!/usr/bin/env python3
# Copyright (c) 2026 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that undo preserves pegout maturity across a deep reorganization."""

from decimal import Decimal

from test_framework.test_framework import LitecoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class MWEBUndoTest(LitecoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-keypool=100"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        if self.options.descriptors:
            self.skip_if_no_sqlite()
        else:
            self.skip_if_no_bdb()

    def run_test(self):
        node = self.nodes[0]
        self.setup_mweb_chain(node, pegin_amount=Decimal("10"))
        wallet = node.get_wallet_rpc(self.default_wallet_name)

        self.log.info("Create a pegout for a wallet that learns it from HogEx")
        node.createwallet("mweb_sender", descriptors=self.options.descriptors)
        sender = node.get_wallet_rpc("mweb_sender")
        node.createwallet("pegout_receiver", descriptors=self.options.descriptors)
        receiver = node.get_wallet_rpc("pegout_receiver")
        wallet.sendtoaddress(sender.getnewaddress(address_type="mweb"), Decimal("5"))
        self.generate(node, 1, sync_fun=self.no_op)

        pegout_address = receiver.getnewaddress()
        node.unloadwallet("pegout_receiver")
        sender.sendtoaddress(pegout_address, Decimal("4"))
        pegout_block = self.generate(node, 1, sync_fun=self.no_op)[0]
        hogex = node.getblock(pegout_block, 2)["tx"][-1]
        pegout = next(
            output for output in hogex["vout"]
            if output["scriptPubKey"].get("address") == pegout_address
        )
        node.loadwallet("pegout_receiver")
        receiver = node.get_wallet_rpc("pegout_receiver")
        receiver.rescanblockchain(0)

        self.log.info("Mature and spend the pegout")
        maturity_blocks = self.generate(node, 5, sync_fun=self.no_op)
        raw_tx = receiver.createrawtransaction(
            [{"txid": hogex["txid"], "vout": pegout["n"]}],
            {receiver.getnewaddress(): pegout["value"] - Decimal("0.001")},
        )
        signed_tx = receiver.signrawtransactionwithwallet(raw_tx)
        assert signed_tx["complete"]
        spend_txid = node.sendrawtransaction(signed_tx["hex"])
        self.generate(node, 1, sync_fun=self.no_op)
        assert_equal(node.getrawmempool(), [])

        self.log.info("Disconnect below maturity and reject the restored pegout spend")
        node.invalidateblock(maturity_blocks[0])
        assert_equal(node.getbestblockhash(), pegout_block)
        assert spend_txid not in node.getrawmempool()
        assert node.gettxout(hogex["txid"], pegout["n"]) is not None
        assert_raises_rpc_error(
            -26,
            "bad-txns-premature-spend-of-pegout",
            node.sendrawtransaction,
            signed_tx["hex"],
        )


if __name__ == "__main__":
    MWEBUndoTest().main()
