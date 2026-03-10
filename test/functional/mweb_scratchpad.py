#!/usr/bin/env python3
# Copyright (c) 2021 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Basic MWEB Wallet test"""

from typing import List
from test_framework.test_framework import LitecoinTestFramework, TestNode
from test_framework.util import assert_equal

class MWEBScratchpad(LitecoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4
        self.extra_args = [['-whitelist=noban@127.0.0.1'],['-whitelist=noban@127.0.0.1'],['-whitelist=noban@127.0.0.1'],[]]  # immediate tx relay

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def multiple_pegouts(self):
        node0 = self.nodes[0]
        node3 = self.nodes[3]

        n3_mweb_addr = node3.getnewaddress(address_type='mweb')
        funding_txid = node0.sendtoaddress(n3_mweb_addr, 25)
        self.generate(node0, 1, sync_fun=self.sync_all)
        
        n0_ltc_addr1 = node0.getnewaddress()
        n0_ltc_addr2 = node0.getnewaddress()
        n3_ltc_addr = node3.getnewaddress()
        tx = node3.send(outputs=[{n0_ltc_addr1:10.0}, {n0_ltc_addr2:5.0}])
        

    def pegin_tx(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        node2 = self.nodes[2]

        n1_ltc_addr = node1.getnewaddress()
        node0.sendtoaddress(n1_ltc_addr, 15)
        self.generate(node0, 1, sync_fun=self.sync_all)
        
        n2_pegin_addr = node2.getnewaddress(address_type='mweb')
        n1_change_addr = node1.getnewaddress()
        pegin_send_result = node1.send(outputs=[{n2_pegin_addr:10.0}], options={'change_address':n1_change_addr})
        #print(pegin_send_result)
        self.generate(node0, 1, sync_fun=self.sync_all)

        n1_pegin_tx = node1.gettransaction(txid=pegin_send_result['txid'], verbose=True)
        #print(n1_pegin_tx)
        
        n2_pegin_tx = node2.gettransaction(txid=pegin_send_result['txid'], verbose=True)
        #print(n2_pegin_tx['hex'])
        block_id = self.generate(node2, 1, sync_fun=self.sync_all)[0]
        #print(node2.getblock(blockhash=block_id, verbosity=1))


    def basic_reorg_test(self):
        self.log.info("Create all pre-MWEB blocks")

        self.log.info("Pegin some coins in pegin_tx1. pegin_tx1 should be in the mempool")
        node0_mweb_addr = self.nodes[0].getnewaddress(address_type='mweb')
        pegin_tx1_id = self.nodes[0].sendtoaddress(node0_mweb_addr, 100)
        self.sync_all()

        assert_equal(set(self.nodes[1].getrawmempool()), {pegin_tx1_id})

        self.log.info("Mine pegin_tx1 in block0a, and mine a few blocks on top. mempool should be empty")
        block0a = self.generate(self.nodes[0], 4)[0]

        assert_equal(len(self.nodes[1].getrawmempool()), 0)

        self.log.info("Invalidate block0a. pegin_tx1 should be back in the mempool")
        self.nodes[1].invalidateblock(block0a)
        assert_equal(set(self.nodes[1].getrawmempool()), {pegin_tx1_id})

        self.log.info("Generate block0b. pegin_tx1 should be included in the block")
        block0b_hash = self.generate(self.nodes[1], 1, sync_fun=self.no_op)[0]

        block0b_txs = self.nodes[1].getblock(block0b_hash, 2)['tx']
        assert_equal(len(block0b_txs), 3)
        assert_equal(block0b_txs[1]['txid'], pegin_tx1_id)

        self.generate(self.nodes[1], 5)
       
    # MW: TODO - Run test twice, once with 'sendtoaddress', and once with just 'send'
    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        node2 = self.nodes[2]

        self.log.info("Setting up MWEB chain")
        self.setup_mweb_chain(node0)
        self.sync_all()

        # self.multiple_pegouts()
        self.pegin_tx()
        self.disconnect_nodes(0, 2)
        self.disconnect_nodes(1, 2)
        
        self.generate(node2, 1, sync_fun=self.no_op)
        n2_pegout_addr = node2.getnewaddress(address_type='bech32')
        pegout_txid = node2.sendtoaddress(n2_pegout_addr, 7)
        print(node2.gettransaction(txid=pegout_txid, verbose=True))

        assert_equal(set(node2.getrawmempool()), {pegout_txid})
        raw_pegout_tx = node2.getrawtransaction(pegout_txid)
        self.generate(node0, 2, sync_fun=self.no_op)
        
        self.connect_nodes(0, 2)
        self.sync_blocks()
        assert_equal(set(node2.getrawmempool()), {pegout_txid})


if __name__ == '__main__':
    MWEBScratchpad().main()
