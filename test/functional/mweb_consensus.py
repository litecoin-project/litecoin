#!/usr/bin/env python3
# Copyright (c) 2021 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test MWEB consensus rules"""

from decimal import Decimal

from test_framework.ltc_util import get_hog_addr_txout
from test_framework.test_framework import LitecoinTestFramework
from test_framework.util import assert_equal


class MWEBConsensusTest(LitecoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.extra_args = [['-whitelist=noban@127.0.0.1'],['-whitelist=noban@127.0.0.1']]  # immediate tx relay
        self.num_nodes = 2

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.log.info("Setup MWEB chain")
        self.setup_mweb_chain(self.nodes[0])
        self.sync_blocks()

        # TODO: Test duplicate pegins
        self.run_issue_1006_regression_test()

    def send_mweb_pegin(self, node, amount, recipient_addr: str):
        outputs = [{recipient_addr: amount}]
        options = {
            'add_to_wallet': True,
            'change_address': node.getnewaddress(),
            'include_unsafe': True
        }
        return node.send(outputs=outputs, options=options)

    def run_issue_1006_regression_test(self):
        self.log.info("Test issue 1006 regression")

        node0 = self.nodes[0]
        node1 = self.nodes[1]
        pegin_amount = Decimal("25")
        initial_mweb_amount = get_hog_addr_txout(node0).get_amount()

        #
        # Pegin funds from node0(miner) to node1
        #
        n1_mweb_addr1 = node1.getnewaddress(address_type='mweb')
        tx1_id = self.send_mweb_pegin(node0, pegin_amount, n1_mweb_addr1)['txid']
        tx1 = node0.gettransaction(tx1_id, False, True)
        assert_equal(tx1['confirmations'], 0)
        assert_equal(tx1['amount'], -pegin_amount)
        self.sync_mempools()
        assert_equal(set(node0.getrawmempool()), {tx1_id})
        assert_equal(set(node1.getrawmempool()), {tx1_id})

        #
        # Pegout the entire coin back to node0(miner)
        #
        n0_ltc_addr1 = node0.getnewaddress()
        n1_ltc_addr1 = node1.getnewaddress()
        outputs = [{n0_ltc_addr1: pegin_amount}]
        options = {
            'add_to_wallet': True,
            'subtract_fee_from_outputs': [0],
            'include_unsafe': True
        }
        tx2_id = node1.send(outputs=outputs, options=options)['txid']
        tx2 = node1.gettransaction(tx2_id)
        assert_equal(tx2['confirmations'], 0)
        assert tx2['fee'] < 0
        assert_equal(tx2['amount'], -(pegin_amount + tx2['fee']))
        self.sync_mempools()
        assert_equal(set(node0.getrawmempool()), {tx1_id, tx2_id})
        assert_equal(set(node1.getrawmempool()), {tx1_id, tx2_id})

        block_id = self.generatetoaddress(node1, 1, n1_ltc_addr1)[0]
        self.sync_all()
        assert_equal(set(node0.getrawmempool()), {tx2_id})
        assert_equal(set(node1.getrawmempool()), {tx2_id})

        block_txs = node1.getblock(block_id, 1)['tx']
        assert tx1_id in block_txs
        assert tx2_id not in block_txs

        block_id = self.generatetoaddress(node1, 1, n1_ltc_addr1)[0]
        self.sync_all()
        assert_equal(node0.getrawmempool(), [])
        assert_equal(node1.getrawmempool(), [])

        assert_equal(node1.gettransaction(tx2_id)['confirmations'], 1)

        received = node0.listreceivedbyaddress(minconf=0, address_filter=n0_ltc_addr1)
        assert_equal(len(received), 1)
        assert_equal(received[0]['amount'], pegin_amount + tx2['fee'])
        assert_equal(received[0]['confirmations'], 1)
        assert_equal(get_hog_addr_txout(node0).get_amount(), initial_mweb_amount)

if __name__ == '__main__':
    MWEBConsensusTest().main()
