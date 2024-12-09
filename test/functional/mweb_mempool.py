#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Tests mempool functionality for MWEB transactions
"""

from test_framework.ltc_util import mweb_aggregate_txs
from test_framework.messages import CTransaction, tx_from_hex
from test_framework.test_framework import LitecoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

class MWEBMempoolTest(LitecoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [
            ['-whitelist=noban@127.0.0.1'],
            ['-whitelist=noban@127.0.0.1'],
            ['-whitelist=noban@127.0.0.1'],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def test_rpc_serial_versions(self):        
        self.stop_nodes()
        self.start_node(0, extra_args=['-whitelist=noban@127.0.0.1', '-rpcserialversion=0'])
        self.start_node(1, extra_args=['-whitelist=noban@127.0.0.1', '-rpcserialversion=1'])
        self.start_node(2, extra_args=['-whitelist=noban@127.0.0.1', '-rpcserialversion=2'])
        self.connect_nodes(0, 1)
        self.connect_nodes(0, 2)
        self.connect_nodes(1, 2)
        
        self.log.info("Create an MWEB-to-MWEB transaction")
        txid = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(address_type='mweb'), 2)
        self.sync_mempools()

        self.log.info("Assert txid is returned in getrawmempool but tx not returned from getmempoolentry for rpcserialversion=0")
        assert_equal([txid], self.nodes[0].getrawmempool())
        assert_raises_rpc_error(-22, "MWEB-only transaction not serializable for rpcserialversion<2", self.nodes[0].getmempoolentry, txid)

        self.log.info("Assert txid is returned in getrawmempool but tx not returned from getmempoolentry for rpcserialversion=1")
        assert_equal([txid], self.nodes[1].getrawmempool())
        assert_raises_rpc_error(-22, "MWEB-only transaction not serializable for rpcserialversion<2", self.nodes[1].getmempoolentry, txid)

        self.log.info("Assert txid is returned in getrawmempool and tx is returned for getmempoolentry for rpcserialversion=2")
        assert_equal([txid], self.nodes[2].getrawmempool())
        assert self.nodes[2].getmempoolentry(txid) is not None
        
        self.log.info("Generate a block to clear all mempools")
        self.generatetoaddress(self.nodes[0], nblocks=1, address=self.nodes[1].getnewaddress(), sync_fun=self.sync_all)[0]
        
    def test_mweb_aggregation(self):
        """
        Tests aggregating 2 MWEB transactions together.
        The aggregated transaction should be accepted by the mempool if neither of the original 2 txs are in it.
        """
        self.log.info("Restart all nodes, not reconnecting them")
        self.stop_nodes()
        self.start_nodes()
        
        self.log.info("Create MWEB-to-MWEB transactions")
        n0_txid = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(address_type='mweb'), 2)
        n0_tx: CTransaction = tx_from_hex(self.nodes[0].getrawtransaction(n0_txid))
        
        n1_txid = self.nodes[1].sendtoaddress(self.nodes[1].getnewaddress(address_type='mweb'), 2)
        n1_tx: CTransaction = tx_from_hex(self.nodes[1].getrawtransaction(n1_txid))
        
        self.log.info("Aggregate the transactions")
        aggregated_tx = CTransaction()
        aggregated_tx.mweb_tx = mweb_aggregate_txs([n0_tx.mweb_tx, n1_tx.mweb_tx])

        # TODO: Ensure the following scenarios just ignore the error, rather than disconnecting from the peer
        self.log.info("Test adding individual txs and the aggregated tx to mempool")
        assert_raises_rpc_error(-26, "txn-mempool-conflict", self.nodes[0].sendrawtransaction, aggregated_tx.serialize_with_mweb().hex())
        assert_raises_rpc_error(-26, "txn-mempool-conflict", self.nodes[1].sendrawtransaction, aggregated_tx.serialize_with_mweb().hex())
        self.nodes[2].sendrawtransaction(aggregated_tx.serialize_with_mweb().hex())
        assert_raises_rpc_error(-26, "txn-mempool-conflict", self.nodes[2].sendrawtransaction, n0_tx.serialize_with_mweb().hex())
        assert_raises_rpc_error(-26, "txn-mempool-conflict", self.nodes[2].sendrawtransaction, n1_tx.serialize_with_mweb().hex())
        self.nodes[1].sendrawtransaction(n0_tx.serialize_with_mweb().hex())
        self.nodes[0].sendrawtransaction(n1_tx.serialize_with_mweb().hex())

        expected_kernels = set([kernel.kernel_excess.to_hex() for kernel in aggregated_tx.mweb_tx.body.mweb_kernels])

        self.log.info("Verify that each node is able to generate a block on top of their current mempool state")
        n0_block_hash = self.generatetoaddress(self.nodes[0], nblocks=1, address=self.nodes[0].getnewaddress(), sync_fun=self.no_op)[0]
        assert set(self.nodes[0].getblock(n0_block_hash)['mweb']['kernels']) == expected_kernels
        
        n1_block_hash = self.generatetoaddress(self.nodes[1], nblocks=1, address=self.nodes[1].getnewaddress(), sync_fun=self.no_op)[0]
        assert set(self.nodes[1].getblock(n1_block_hash)['mweb']['kernels']) == expected_kernels
        
        n2_block_hash = self.generatetoaddress(self.nodes[2], nblocks=1, address=self.nodes[1].getnewaddress(), sync_fun=self.no_op)[0]
        assert set(self.nodes[2].getblock(n2_block_hash)['mweb']['kernels']) == expected_kernels

    def test_reorg(self):
        """
        Tests adding an MWEB transaction to a block, reorging to another chain without that transaction,
        and confirming the MWEB transaction is added back to the mempool.
        """
        self.log.info("Restart all nodes, not reconnecting them")
        self.stop_nodes()
        self.start_nodes()
        
        self.log.info("Create an MWEB transaction on node 0, and mine it in a block")
        mweb_txid = self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(address_type='mweb'), 1)
        assert_equal([mweb_txid], self.nodes[0].getrawmempool())
        
        self.generatetoaddress(self.nodes[0], nblocks=1, address=self.nodes[0].getnewaddress(), sync_fun=self.no_op)
        assert_equal([], self.nodes[0].getrawmempool())

        self.log.info("Mine a longer chain on node 2, and connect with node 0. Node 0 should reorg to the longer chain.")
        n2_highest_block = self.generatetoaddress(self.nodes[2], nblocks=5, address=self.nodes[2].getnewaddress(), sync_fun=self.no_op)[-1]
        self.connect_nodes(2, 0)
        self.sync_blocks([self.nodes[0], self.nodes[2]], timeout=5)
        assert_equal(self.nodes[0].getbestblockhash(), n2_highest_block)

        self.log.info("Ensure the MWEB transaction is back in node 0's mempool")
        assert_equal([mweb_txid], self.nodes[0].getrawmempool())

        # TODO: Test when mweb_tx is no longer valid
        # TODO: Test when attempting to spend an immature pegout
        
    def run_test(self):
        self.log.info("Setup MWEB chain")
        self.setup_mweb_chain(self.nodes[0])
        self.sync_blocks()
        
        self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 15)
        self.generatetoaddress(self.nodes[0], nblocks=1, address=self.nodes[0].getnewaddress(), sync_fun=self.sync_all)
        
        self.log.info("Pegin some coins - nodes 0 and 1")
        self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(address_type='mweb'), 10)
        self.nodes[1].sendtoaddress(self.nodes[1].getnewaddress(address_type='mweb'), 10)
        self.sync_all()
        
        self.generatetoaddress(self.nodes[0], nblocks=1, address=self.nodes[0].getnewaddress(), sync_fun=self.sync_all)
        
        self.test_rpc_serial_versions()
        self.test_mweb_aggregation()
        self.test_reorg()

        # TODO: Test with orphaned MWEB txs

if __name__ == '__main__':
    MWEBMempoolTest().main()







 ###########
 # Code below proves v21 has a reorg issue
 ###########
#  #!/usr/bin/env python3
# # Copyright (c) 2020 The Bitcoin Core developers
# # Distributed under the MIT software license, see the accompanying
# # file COPYING or http://www.opensource.org/licenses/mit-license.php.
# """
# Tests mempool functionality for MWEB transactions
# """

# from test_framework.ltc_util import mweb_aggregate_txs
# from test_framework.messages import CTransaction, tx_from_hex
# from test_framework.test_framework import LitecoinTestFramework
# from test_framework.util import assert_equal, assert_raises_rpc_error

# class MWEBMempoolTest(LitecoinTestFramework):
#     def set_test_params(self):
#         self.setup_clean_chain = True
#         self.num_nodes = 3
#         self.extra_args = [
#             ['-whitelist=noban@127.0.0.1'],
#             ['-whitelist=noban@127.0.0.1'],
#             ['-whitelist=noban@127.0.0.1'],
#         ]
        
#     def setup_nodes(self):
#         self.add_nodes(self.num_nodes, extra_args=self.extra_args, versions=[
#             210202,
#             210202,
#             210202,
#         ])

#         self.start_nodes()
#         #self.import_deterministic_coinbase_privkeys()

#     def skip_test_if_missing_module(self):
#         self.skip_if_no_wallet()

#     def test_rpc_serial_versions(self):
#         self.stop_nodes()
#         self.start_node(0, extra_args=['-whitelist=noban@127.0.0.1', '-rpcserialversion=0', '-wallet=w1'])
#         self.start_node(1, extra_args=['-whitelist=noban@127.0.0.1', '-rpcserialversion=1', '-wallet=w2'])
#         self.start_node(2, extra_args=['-whitelist=noban@127.0.0.1', '-rpcserialversion=2', '-wallet=w3'])
#         self.connect_nodes(0, 1)
#         self.connect_nodes(0, 2)
#         self.connect_nodes(1, 2)
        
#         self.log.info("Create an MWEB-to-MWEB transaction")
#         txid = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(address_type='mweb'), 2)
#         self.sync_mempools()

#         self.log.info("Assert txid is returned in getrawmempool but tx not returned from getmempoolentry for rpcserialversion=0")
#         assert_equal([txid], self.nodes[0].getrawmempool())
#         #assert_raises_rpc_error(-22, "MWEB-only transaction not serializable for rpcserialversion<2", self.nodes[0].getmempoolentry, txid)

#         self.log.info("Assert txid is returned in getrawmempool but tx not returned from getmempoolentry for rpcserialversion=1")
#         assert_equal([txid], self.nodes[1].getrawmempool())
#         #assert_raises_rpc_error(-22, "MWEB-only transaction not serializable for rpcserialversion<2", self.nodes[1].getmempoolentry, txid)

#         self.log.info("Assert txid is returned in getrawmempool and tx is returned for getmempoolentry for rpcserialversion=2")
#         assert_equal([txid], self.nodes[2].getrawmempool())
#         assert self.nodes[2].getmempoolentry(txid) is not None
        
#         self.log.info("Generate a block to clear all mempools")
#         self.generatetoaddress(self.nodes[0], nblocks=1, address=self.nodes[1].getnewaddress(), sync_fun=self.sync_all)[0]
        
#     def test_mweb_aggregation(self):
#         """
#         Tests aggregating 2 MWEB transactions together.
#         The aggregated transaction should be accepted by the mempool if neither of the original 2 txs are in it.
#         """
#         self.log.info("Restart all nodes, not reconnecting them")
#         self.stop_nodes()
#         self.start_nodes(extra_args = [
#             ['-wallet=w1'],
#             ['-wallet=w2'],
#             ['-wallet=w3'],
#         ])
        
#         self.log.info("Create MWEB-to-MWEB transactions")
#         n0_txid = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(address_type='mweb'), 2)
#         n0_tx: CTransaction = tx_from_hex(self.nodes[0].getrawtransaction(n0_txid))
        
#         n1_txid = self.nodes[1].sendtoaddress(self.nodes[1].getnewaddress(address_type='mweb'), 2)
#         n1_tx: CTransaction = tx_from_hex(self.nodes[1].getrawtransaction(n1_txid))
        
#         self.log.info("Aggregate the transactions")
#         aggregated_tx = CTransaction()
#         aggregated_tx.mweb_tx = mweb_aggregate_txs([n0_tx.mweb_tx, n1_tx.mweb_tx])

#         # TODO: Ensure the following scenarios just ignore the error, rather than disconnecting from the peer
#         self.log.info("Test adding individual txs and the aggregated tx to mempool")
#         #assert_raises_rpc_error(-26, "txn-mempool-conflict", self.nodes[0].sendrawtransaction, aggregated_tx.serialize_with_mweb().hex())
#         #assert_raises_rpc_error(-26, "txn-mempool-conflict", self.nodes[1].sendrawtransaction, aggregated_tx.serialize_with_mweb().hex())
#         #self.nodes[2].sendrawtransaction(aggregated_tx.serialize_with_mweb().hex())
#         #assert_raises_rpc_error(-26, "txn-mempool-conflict", self.nodes[2].sendrawtransaction, n0_tx.serialize_with_mweb().hex())
#         #assert_raises_rpc_error(-26, "txn-mempool-conflict", self.nodes[2].sendrawtransaction, n1_tx.serialize_with_mweb().hex())
#         self.nodes[1].sendrawtransaction(n0_tx.serialize_with_mweb().hex())
#         self.nodes[0].sendrawtransaction(n1_tx.serialize_with_mweb().hex())

#         expected_kernels = set([kernel.kernel_excess.to_hex() for kernel in aggregated_tx.mweb_tx.body.mweb_kernels])

#         self.log.info("Verify that each node is able to generate a block on top of their current mempool state")
#         n0_block_hash = self.generatetoaddress(self.nodes[0], nblocks=1, address=self.nodes[0].getnewaddress(), sync_fun=self.no_op)[0]
#         assert set(self.nodes[0].getblock(n0_block_hash)['mweb']['kernels']) == expected_kernels
        
#         n1_block_hash = self.generatetoaddress(self.nodes[1], nblocks=1, address=self.nodes[1].getnewaddress(), sync_fun=self.no_op)[0]
#         assert set(self.nodes[1].getblock(n1_block_hash)['mweb']['kernels']) == expected_kernels
        
#         n2_block_hash = self.generatetoaddress(self.nodes[2], nblocks=1, address=self.nodes[1].getnewaddress(), sync_fun=self.no_op)[0]
#         #assert set(self.nodes[2].getblock(n2_block_hash)['mweb']['kernels']) == expected_kernels

#     def test_reorg(self):
#         """
#         Tests adding an MWEB transaction to a block, reorging to another chain without that transaction,
#         and confirming the MWEB transaction is added back to the mempool.
#         """
#         self.log.info("Restart all nodes, not reconnecting them")
#         self.stop_nodes()
#         self.start_nodes(extra_args = [
#             ['-wallet=w1'],
#             ['-wallet=w2'],
#             ['-wallet=w3'],
#         ])
        
#         self.log.info("Create an MWEB transaction on node 0, and mine it in a block")
#         mweb_txid = self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(address_type='mweb'), 1)
#         assert_equal([mweb_txid], self.nodes[0].getrawmempool())
        
#         self.generatetoaddress(self.nodes[0], nblocks=1, address=self.nodes[0].getnewaddress(), sync_fun=self.no_op)
#         assert_equal([], self.nodes[0].getrawmempool())

#         self.log.info("Mine a longer chain on node 2, and connect with node 0. Node 0 should reorg to the longer chain.")
#         n2_highest_block = self.generatetoaddress(self.nodes[2], nblocks=5, address=self.nodes[2].getnewaddress(), sync_fun=self.no_op)[-1]
#         self.connect_nodes(2, 0)
#         self.sync_blocks([self.nodes[0], self.nodes[2]], timeout=5)
#         assert_equal(self.nodes[0].getbestblockhash(), n2_highest_block)

#         self.log.info("Ensure the MWEB transaction is back in node 0's mempool")
#         assert_equal([mweb_txid], self.nodes[0].getrawmempool())

#         # TODO: Test when mweb_tx is no longer valid
#         # TODO: Test when attempting to spend an immature pegout
        
#     def run_test(self):
#         self.log.info("Setup MWEB chain")
#         self.nodes[0].rpc.createwallet(wallet_name="w1")
#         self.nodes[1].rpc.createwallet(wallet_name="w2")
#         self.nodes[2].rpc.createwallet(wallet_name="w3")
#         generate_addr = self.nodes[0].getnewaddress()

#         # Create all pre-MWEB blocks
#         self.generatetoaddress(self.nodes[0], nblocks=431, address=generate_addr, sync_fun=self.no_op)

#         # Pegin some coins
#         mweb_addr = self.nodes[0].getnewaddress(address_type='mweb')
#         pegin_amount = Decimal(1.0)
#         self.nodes[0].sendtoaddress(mweb_addr, pegin_amount)

#         # Create some blocks - activate MWEB
#         self.generatetoaddress(self.nodes[0], nblocks=1, address=generate_addr, sync_fun=self.no_op)

    
#         self.setup_mweb_chain(self.nodes[0])
#         self.sync_blocks()
        
#         self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 15)
#         self.generatetoaddress(self.nodes[0], nblocks=1, address=self.nodes[0].getnewaddress(), sync_fun=self.sync_all)
        
#         self.log.info("Pegin some coins - nodes 0 and 1")
#         self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(address_type='mweb'), 10)
#         self.nodes[1].sendtoaddress(self.nodes[1].getnewaddress(address_type='mweb'), 10)
#         self.sync_all()
        
#         self.generatetoaddress(self.nodes[0], nblocks=1, address=self.nodes[0].getnewaddress(), sync_fun=self.sync_all)
        
#         self.test_rpc_serial_versions()
#         self.test_mweb_aggregation()
#         self.test_reorg()

#         # TODO: Test with orphaned MWEB txs

# if __name__ == '__main__':
#     MWEBMempoolTest().main()
