#!/usr/bin/env python3
# Copyright (c) 2021 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test MWEB consensus rules"""

import json
from test_framework.test_framework import LitecoinTestFramework
from test_framework.util import assert_equal, CustomJSONEncoder

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

    def send_tx_with_no_change(self, node, amount, recipient_addr: str):
        outputs = [{recipient_addr: 25}]
        options = {
            'add_to_wallet': True,
            'change_address': node.getnewaddress(),
            #'subtract_fee_from_outputs': [0],
            'include_unsafe': True
        }
        return node.send(outputs=outputs, options=options)

    def run_issue_1006_regression_test(self):
        self.log.info("Test issue 1006 regression")
        
        node0 = self.nodes[0]
        node1 = self.nodes[1]

        #
        # Pegin funds from node0(miner) to node1
        #
        n1_mweb_addr1 = node1.getnewaddress(address_type='mweb')
        tx1_id = self.send_tx_with_no_change(node0, 50, n1_mweb_addr1)['txid'] #node0.sendtoaddress(n1_mweb_addr1, 50) # node0.sendall(recipients=[n1_mweb_addr1])['txid']
        tx1 = node0.gettransaction(tx1_id, False, True)
        output_id = [o['mweb_out'] for o in tx1['details'] if o['amount'] == 0.0][0]
        print(f'Output ID: {output_id}')
        self.sync_mempools()
        #print(f"Tx1: {json.dumps(tx1, cls=CustomJSONEncoder, indent=4)}")

        #
        # Pegout the entire coin back to node0(miner)
        #
        n0_ltc_addr1 = node0.getnewaddress()
        n1_ltc_addr1 = node1.getnewaddress()
        outputs = [{n0_ltc_addr1: 25}]
        options = {
            'add_to_wallet': True,
            #'change_address': n1_ltc_addr1,
            'subtract_fee_from_outputs': [0],
            'include_unsafe': True
        }
        tx2_id = node1.send(outputs=outputs, options=options)['txid']
        print(f"Tx2 ID: {tx2_id}")
        tx2 = node1.getrawtransaction(tx2_id, False)
        print(f"Tx2: {json.dumps(tx2, cls=CustomJSONEncoder, indent=4)}")
        print(f"Node1 Transactions: {json.dumps(node1.listwallettransactions(), cls=CustomJSONEncoder, indent=4)}")

        block_id = self.generatetoaddress(node1, 1, n1_ltc_addr1)[0]
        print(f"Block: {json.dumps(node1.getblock(block_id, True), cls=CustomJSONEncoder, indent=4)}")

if __name__ == '__main__':
    MWEBConsensusTest().main()
