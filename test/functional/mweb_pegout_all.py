#!/usr/bin/env python3
# Copyright (c) 2021 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify that we can pegout all coins in the MWEB"""

from decimal import Decimal
from html.entities import name2codepoint
from sys import setdlopenflags
from test_framework.test_framework import LitecoinTestFramework
from test_framework.util import assert_equal, satoshi_round
from test_framework.messages import COIN, CTransaction, from_hex
from test_framework.ltc_util import get_hog_addr_txout

class MWEBPegoutAllTest(LitecoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [
            [
                '-whitelist=noban@127.0.0.1',  # immediate tx relay
            ],
            []
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node1 = self.nodes[1]
        PEGIN_AMOUNT = Decimal(10.0)
        
        self.log.info("Setup MWEB chain")
        self.setup_mweb_chain(node, pegin_amount=PEGIN_AMOUNT)
        
        self.log.info("Check that pegged in amount is 10")
        hog_addr_txout = get_hog_addr_txout(node)
        assert_equal(hog_addr_txout.get_amount(), PEGIN_AMOUNT)

        self.log.info("Sending MWEB coins to node 1")
        node1_mweb1 = node1.getnewaddress(address_type='mweb')
        mweb_to_mweb_tx = node.sendtoaddress(address=node1_mweb1, amount=PEGIN_AMOUNT, subtractfeefromamount=True)
        mweb_to_mweb_fee = abs(node.gettransaction(mweb_to_mweb_tx)['fee'])

        assert_equal(len(node.getrawmempool()), 1)
        self.generate(node, 1)[0]
        assert_equal(len(node.getrawmempool()), 0)
        self.sync_all()

        self.log.info("Check that pegged in amount is (10 - fee)")
        pegged_in_amount = get_hog_addr_txout(node).get_amount()
        assert_equal(pegged_in_amount, PEGIN_AMOUNT - mweb_to_mweb_fee)

        self.log.info("Pegout all coins")
        total_balance = node1.getbalance()
        assert_equal(pegged_in_amount, total_balance)
        pegout_txid = node1.sendtoaddress(address=node1.getnewaddress(), amount=pegged_in_amount, subtractfeefromamount=True)

        pegout_tx = CTransaction()
        pegout_tx = from_hex(pegout_tx, node1.gettransaction(pegout_txid)['hex'])
        self.sync_all()

        assert_equal(len(node.getrawmempool()), 1)
        self.generate(node, 1, sync_fun=self.no_op)[0]
        assert_equal(len(node.getrawmempool()), 0)

        self.log.info("Check that pegged in amount is 0")
        hog_addr_txout = get_hog_addr_txout(node)
        assert_equal(hog_addr_txout.nValue, 0.0)

        self.log.info("Ensure we can mine the next block")
        self.generate(node, 1, sync_fun=self.no_op)

if __name__ == '__main__':
    MWEBPegoutAllTest().main()
