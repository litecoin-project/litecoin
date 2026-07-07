#!/usr/bin/env python3
# Copyright (c) 2026 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test upgrading partial MWEB wallet entries when the full tx later reappears."""

import shutil
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import LitecoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class MWEBWalletPartialUpgradeTest(LitecoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [['-keypool=100']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        if self.options.descriptors:
            self.skip_if_no_sqlite()
        else:
            self.skip_if_no_bdb()

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Setting up MWEB funds in the sender wallet")
        self.setup_mweb_chain(node, pegin_amount=Decimal("1.0"))
        sender_wallet = node.get_wallet_rpc(self.default_wallet_name)

        self.log.info("Creating and snapshotting a receiver wallet before the receive")
        receiver_name = "receiver"
        node.createwallet(receiver_name, descriptors=self.options.descriptors)
        self.stop_node(0)
        snapshot_name = self.snapshot_wallet(self.nodes[0], receiver_name)
        self.start_node(0, self.extra_args[0])
        node = self.nodes[0]
        sender_wallet = node.get_wallet_rpc(self.default_wallet_name)
        receiver_wallet = self.get_or_load_wallet(node, receiver_name)

        self.log.info("Receive and confirm an MWEB transaction")
        amount = Decimal("0.5")
        receiver_addr = receiver_wallet.getnewaddress(address_type="mweb")
        txid = sender_wallet.sendtoaddress(receiver_addr, amount)
        sender_tx_hex = sender_wallet.gettransaction(txid)["hex"]
        blockhash = self.generate(node, 1, sync_fun=self.no_op)[0]
        confirmed_tx = receiver_wallet.gettransaction(txid)
        assert_equal(confirmed_tx["amount"], amount)
        assert_equal(confirmed_tx["confirmations"], 1)
        assert_equal(receiver_wallet.getwalletinfo()["txcount"], 1)
        self.assert_total_mine_balance(receiver_wallet, amount)

        self.log.info("Restore the receiver wallet snapshot and rescan into the partial state")
        self.stop_node(0)
        self.restore_wallet(self.nodes[0], receiver_name, snapshot_name)
        self.start_node(0, self.extra_args[0])
        node = self.nodes[0]
        sender_wallet = node.get_wallet_rpc(self.default_wallet_name)
        receiver_wallet = self.get_or_load_wallet(node, receiver_name)
        receiver_wallet.rescanblockchain(0)

        assert_equal(receiver_wallet.getwalletinfo()["txcount"], 1)
        self.assert_total_mine_balance(receiver_wallet, amount)
        assert self.find_listwallettransactions_entry(receiver_wallet, txid) is None
        assert_raises_rpc_error(-5, "Invalid or non-wallet transaction id", receiver_wallet.listwallettransactions, txid)
        assert_raises_rpc_error(-5, "Invalid or non-wallet transaction id", receiver_wallet.gettransaction, txid)

        self.log.info("Invalidate the block and rebroadcast the full transaction")
        node.invalidateblock(blockhash)
        assert_equal(node.sendrawtransaction(sender_tx_hex), txid)
        self.wait_until(lambda: txid in node.getrawmempool())
        self.wait_until(lambda: self.has_wallet_transaction(receiver_wallet, txid))

        mempool_tx = receiver_wallet.gettransaction(txid)
        assert_equal(mempool_tx["amount"], amount)
        assert_equal(mempool_tx["confirmations"], 0)
        assert_equal(receiver_wallet.getwalletinfo()["txcount"], 1)
        self.assert_total_mine_balance(receiver_wallet, amount)

        self.log.info("Reconfirm the transaction and ensure the partial entry was upgraded in place")
        node.reconsiderblock(blockhash)
        self.wait_until(lambda: node.getbestblockhash() == blockhash)
        self.wait_until(lambda: receiver_wallet.gettransaction(txid)["confirmations"] == 1)

        final_tx = receiver_wallet.gettransaction(txid)
        assert_equal(final_tx["amount"], amount)
        assert_equal(final_tx["confirmations"], 1)
        assert_equal(receiver_wallet.getwalletinfo()["txcount"], 1)
        assert_equal(receiver_wallet.getbalances()["mine"]["trusted"], amount)
        self.assert_total_mine_balance(receiver_wallet, amount)

    def get_or_load_wallet(self, node, wallet_name):
        if wallet_name not in node.listwallets():
            node.loadwallet(wallet_name)
        return node.get_wallet_rpc(wallet_name)

    def snapshot_wallet(self, node, wallet_name, suffix="snapshot"):
        wallet_dir = node.chain_path / "wallets"
        src_path = wallet_dir / wallet_name
        snapshot_name = f"{wallet_name}_{suffix}"
        dst_path = wallet_dir / snapshot_name
        if dst_path.exists():
            shutil.rmtree(dst_path)
        shutil.copytree(src_path, dst_path)
        return snapshot_name

    def restore_wallet(self, node, wallet_name, snapshot_name):
        wallet_dir = node.chain_path / "wallets"
        wallet_path = wallet_dir / wallet_name
        snapshot_path = wallet_dir / snapshot_name
        if wallet_path.exists():
            shutil.rmtree(wallet_path)
        shutil.copytree(snapshot_path, wallet_path)

    def assert_total_mine_balance(self, wallet, expected):
        mine_balances = wallet.getbalances()["mine"]
        total = (
            mine_balances.get("trusted", Decimal("0")) +
            mine_balances.get("untrusted_pending", Decimal("0")) +
            mine_balances.get("immature", Decimal("0"))
        )
        assert_equal(total, expected)

    def has_wallet_transaction(self, wallet, txid):
        try:
            wallet.gettransaction(txid)
            return True
        except JSONRPCException:
            return False

    def find_listwallettransactions_entry(self, wallet, txid):
        for entry in wallet.listwallettransactions():
            if entry.get("txid") == txid:
                return entry
        return None


if __name__ == '__main__':
    MWEBWalletPartialUpgradeTest().main()
