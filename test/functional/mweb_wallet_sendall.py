#!/usr/bin/env python3
# Copyright (c) 2026 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test sendall with MWEB inputs and recipients."""

from decimal import Decimal

from test_framework.test_framework import LitecoinTestFramework
from test_framework.util import assert_equal


class WalletSendallMWEBTest(LitecoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [
            ['-whitelist=noban@127.0.0.1'],
            ['-whitelist=noban@127.0.0.1'],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]

        self.log.info("Setting up an active MWEB chain with both LTC and MWEB funds on node0")
        self.setup_mweb_chain(node0, pegin_amount=Decimal('10'))
        self.sync_all()

        self.log.info("Sweep node0's mixed LTC and MWEB balance to a node1 MWEB address")
        node0_balance = node0.getbalances()["mine"]["trusted"]
        node1_mweb = node1.getnewaddress(address_type='mweb')
        sendall_to_mweb = node0.sendall(recipients=[node1_mweb])
        node0_send_tx = node0.gettransaction(sendall_to_mweb["txid"])
        expected_node1_balance = node0_balance + node0_send_tx["fee"]

        self.sync_mempools()
        self.generate(node1, 1, sync_fun=self.sync_all)
        assert_equal(node1.getbalances()["mine"]["trusted"], expected_node1_balance)

        self.log.info("Sweep node1's MWEB balance back out to a node0 LTC address")
        node1_balance = node1.getbalances()["mine"]["trusted"]
        node0_balances_before_pegout = node0.getbalances()["mine"]
        node0_total_before_pegout = node0_balances_before_pegout["trusted"] + node0_balances_before_pegout["immature"]
        node0_ltc = node0.getnewaddress()
        sendall_to_ltc = node1.sendall(recipients=[node0_ltc])
        node1_send_tx = node1.gettransaction(sendall_to_ltc["txid"])
        expected_pegout_amount = node1_balance + node1_send_tx["fee"]

        self.sync_mempools()
        self.generate(node1, 1, sync_fun=self.sync_all)
        assert_equal(node1.getbalances()["mine"]["trusted"], 0)
        node0_balances_after_pegout = node0.getbalances()["mine"]
        node0_total_after_pegout = node0_balances_after_pegout["trusted"] + node0_balances_after_pegout["immature"]
        assert_equal(node0_total_after_pegout, node0_total_before_pegout + expected_pegout_amount)
        node0_received = node0.listwallettransactions(txid=sendall_to_ltc["txid"])
        assert_equal(len(node0_received), 1)
        assert_equal(node0_received[0]["amount"], expected_pegout_amount)
        assert_equal(node0_received[0]["confirmations"], 1)

        self.log.info("Mine pegout maturity and verify the swept amount becomes trusted")
        self.generate(node1, 5, sync_fun=self.sync_all)
        assert_equal(node1.getbalances()["mine"]["trusted"], 0)
        node0_balances_final = node0.getbalances()["mine"]
        node0_total_final = node0_balances_final["trusted"] + node0_balances_final["immature"]
        assert_equal(node0_total_final, node0_total_after_pegout)
        node0_received = node0.listwallettransactions(txid=sendall_to_ltc["txid"])
        assert_equal(len(node0_received), 1)
        assert_equal(node0_received[0]["amount"], expected_pegout_amount)
        assert_equal(node0_received[0]["confirmations"], 6)


if __name__ == '__main__':
    WalletSendallMWEBTest().main()
