#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Tests mempool functionality for MWEB transactions
"""

from decimal import Decimal
import os

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

    def are_nodes_connected(self, a, b):
        a_subver = "testnode{}".format(b)
        b_subver = "testnode{}".format(a)
        return any(a_subver in peer['subver'] for peer in self.nodes[a].getpeerinfo()) or \
            any(b_subver in peer['subver'] for peer in self.nodes[b].getpeerinfo())

    def disconnect_all_nodes(self):
        for i in range(self.num_nodes):
            for j in range(i + 1, self.num_nodes):
                if self.are_nodes_connected(i, j):
                    self.disconnect_nodes(i, j)

    def connect_all_nodes_to_node0(self, sync_mempools=True):
        for i in range(1, self.num_nodes):
            self.connect_nodes(i, 0)
        if sync_mempools:
            self.sync_all()
        else:
            self.sync_blocks()

    def restart_all_nodes_connected_to_node0(self):
        self.stop_nodes()
        self.start_nodes()
        self.connect_all_nodes_to_node0()

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

    def test_package_mweb_parent_child(self):
        """
        Tests package validation where a child spends an MWEB output created by its package parent.
        """
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        wallet_name = "mweb_package"

        self.log.info("Restart with default transaction serialization")
        self.restart_all_nodes_connected_to_node0()

        self.log.info("Create a dedicated MWEB package wallet")
        node1.createwallet(wallet_name=wallet_name, descriptors=self.options.descriptors)
        package_wallet = node1.get_wallet_rpc(wallet_name)

        self.log.info("Fund the package wallet with a single confirmed MWEB coin")
        funding_addr = package_wallet.getnewaddress(address_type='mweb')
        node0.sendtoaddress(funding_addr, Decimal('3'))
        self.generatetoaddress(node0, nblocks=1, address=node0.getnewaddress(), sync_fun=self.sync_all)
        assert_equal(len(package_wallet.listunspent(addresses=[funding_addr])), 1)
        assert_equal(node0.getrawmempool(), [])

        self.log.info("Build an unrelayed MWEB parent and child on node 1")
        self.disconnect_all_nodes()
        parent_txid = package_wallet.sendall(
            recipients=[package_wallet.getnewaddress(address_type='mweb')],
            options={"add_to_wallet": True},
        )["txid"]
        child_txid = package_wallet.send(
            outputs=[{node0.getnewaddress(address_type='mweb'): Decimal('1')}],
            options={"include_unsafe": True, "add_to_wallet": True},
        )["txid"]

        parent_hex = node1.getrawtransaction(parent_txid)
        child_hex = node1.getrawtransaction(child_txid)

        self.log.info("The MWEB child alone is missing its unconfirmed parent output")
        child_result = node0.testmempoolaccept([child_hex])[0]
        assert_equal(child_result["allowed"], False)
        assert_equal(child_result["reject-reason"], "missing-inputs")

        self.log.info("The sorted MWEB parent-child package is accepted")
        package_result = node0.testmempoolaccept([parent_hex, child_hex])
        assert all(tx_result["allowed"] for tx_result in package_result)

        submit_result = node0.submitpackage([parent_hex, child_hex])
        assert package_result[0]["wtxid"] in submit_result["tx-results"]
        assert package_result[1]["wtxid"] in submit_result["tx-results"]
        assert_equal(set(node0.getrawmempool()), {parent_txid, child_txid})

        self.log.info("Mine the package and unload the temporary wallet")
        self.connect_all_nodes_to_node0(sync_mempools=False)
        self.generatetoaddress(node0, nblocks=1, address=node0.getnewaddress(), sync_fun=self.sync_all)
        assert_equal(node0.getrawmempool(), [])
        node1.unloadwallet(wallet_name)

    def test_mweb_block_conflict_removal(self):
        """
        Tests that a block spend of an MWEB output removes a mempool transaction spending the same output.
        """
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        node2 = self.nodes[2]
        wallet_name = "mweb_conflict"
        clone_name = "mweb_conflict_clone"

        self.log.info("Create a wallet backup with one confirmed MWEB coin")
        node1.createwallet(wallet_name=wallet_name, descriptors=self.options.descriptors)
        original_wallet = node1.get_wallet_rpc(wallet_name)
        funding_addr = original_wallet.getnewaddress(address_type='mweb')
        node0.sendtoaddress(funding_addr, Decimal('2'))
        self.generatetoaddress(node0, nblocks=1, address=node0.getnewaddress(), sync_fun=self.sync_all)
        assert_equal(len(original_wallet.listunspent(addresses=[funding_addr])), 1)

        backup_path = os.path.join(node1.datadir, "mweb_conflict.bak")
        original_wallet.backupwallet(backup_path)
        node2.restorewallet(clone_name, backup_path)
        clone_wallet = node2.get_wallet_rpc(clone_name)
        assert_equal(len(clone_wallet.listunspent(addresses=[funding_addr])), 1)

        self.log.info("Spend the same MWEB coin differently on disconnected nodes")
        self.disconnect_all_nodes()
        stale_txid = original_wallet.send(
            outputs=[{original_wallet.getnewaddress(address_type='mweb'): Decimal('0.5')}],
            options={"add_to_wallet": True},
        )["txid"]
        conflict_txid = clone_wallet.send(
            outputs=[{clone_wallet.getnewaddress(address_type='mweb'): Decimal('0.6')}],
            options={"add_to_wallet": True},
        )["txid"]
        conflict_fee = clone_wallet.gettransaction(conflict_txid)["fee"]
        expected_balance = Decimal('2') + conflict_fee
        expected_change = expected_balance - Decimal('0.6')
        assert stale_txid != conflict_txid
        assert_equal(node1.getrawmempool(), [stale_txid])
        assert_equal(node2.getrawmempool(), [conflict_txid])

        self.log.info("Mine the restored-wallet spend and reconnect to node 1")
        conflict_block = self.generatetoaddress(
            node2,
            nblocks=1,
            address=clone_wallet.getnewaddress(),
            sync_fun=self.no_op,
        )[0]
        assert_equal(node2.getrawmempool(), [])

        self.connect_nodes(1, 2)
        self.sync_blocks([node1, node2], timeout=10)
        assert_equal(node1.getbestblockhash(), conflict_block)
        self.wait_until(lambda: stale_txid not in node1.getrawmempool(), timeout=10)

        def assert_confirmed_conflict():
            stale = original_wallet.gettransaction(stale_txid)
            assert_equal(stale["confirmations"], -1)
            assert_equal(len(stale["walletconflicts"]), 1)
            partial_spend_txid = stale["walletconflicts"][0]

            partial = original_wallet.gettransaction(partial_spend_txid)
            assert_equal(partial["confirmations"], 1)
            assert_equal(partial["blockhash"], conflict_block)
            assert_equal(partial["walletconflicts"], [stale_txid])

            history = original_wallet.listwallettransactions()
            stale_rows = [row for row in history if row["txid"] == stale_txid]
            assert stale_rows
            assert all(row["confirmations"] == -1 for row in stale_rows)

            block_rows = [
                row for row in history
                if row.get("blockhash") == conflict_block and (row["type"] == "Other" or "mweb_out" in row)
            ]
            assert_equal(len(block_rows), 3)
            partial_rows = [row for row in block_rows if row["txid"] == partial_spend_txid]
            assert_equal(len(partial_rows), 1)
            assert_equal(partial_rows[0]["type"], "Other")
            assert_equal(partial_rows[0]["amount"], Decimal('-2'))
            assert_equal(partial_rows[0]["confirmations"], 1)

            receive_rows = [row for row in block_rows if "mweb_out" in row]
            assert_equal(len(receive_rows), 2)
            assert all(row["type"] == "RecvWithAddress" for row in receive_rows)
            assert_equal(sorted(row["amount"] for row in receive_rows), sorted([Decimal('0.6'), expected_change]))
            output_ids = [row["mweb_out"] for row in receive_rows]
            assert_equal(len(set(output_ids)), 2)

            assert_equal(original_wallet.getbalances()["mine"]["trusted"], expected_balance)
            unspent = original_wallet.listunspent()
            assert_equal(sum(output["amount"] for output in unspent), expected_balance)
            assert_equal({output["mweb_out"] for output in unspent}, set(output_ids))
            component_order = [row.get("mweb_out", row["txid"]) for row in block_rows]
            return partial_spend_txid, output_ids, component_order

        self.log.info("Assert the stale spend is conflicted and the unknown winner is represented once")
        partial_spend_txid, output_ids, component_order = assert_confirmed_conflict()

        self.log.info("Disconnect and reconnect the conflict block")
        previous_block = node1.getblock(conflict_block)["previousblockhash"]
        node1.invalidateblock(conflict_block)
        assert_equal(node1.getbestblockhash(), previous_block)
        stale = original_wallet.gettransaction(stale_txid)
        assert_equal(stale["confirmations"], 0)
        assert_equal(stale["walletconflicts"], [])
        assert_raises_rpc_error(-5, "Invalid or non-wallet transaction id", original_wallet.gettransaction, partial_spend_txid)
        assert all(row["txid"] != partial_spend_txid for row in original_wallet.listwallettransactions())
        assert_equal(original_wallet.getbalances()["mine"]["trusted"], Decimal('0'))

        node1.reconsiderblock(conflict_block)
        assert_equal(node1.getbestblockhash(), conflict_block)
        reconnected_partial_txid, reconnected_output_ids, reconnected_component_order = assert_confirmed_conflict()
        assert_equal(reconnected_partial_txid, partial_spend_txid)
        assert_equal(reconnected_output_ids, output_ids)
        assert_equal(reconnected_component_order, component_order)

        self.log.info("Restart with the confirmed conflict and verify wallet reload parity")
        self.restart_node(1)
        node1.loadwallet(wallet_name)
        original_wallet = node1.get_wallet_rpc(wallet_name)
        reloaded_partial_txid, reloaded_output_ids, reloaded_component_order = assert_confirmed_conflict()
        assert_equal(reloaded_partial_txid, partial_spend_txid)
        assert_equal(reloaded_output_ids, output_ids)
        assert_equal(reloaded_component_order, component_order)

        self.log.info("Reconnect all nodes and unload temporary wallets")
        self.connect_nodes(1, 0)
        self.connect_nodes(2, 0)
        self.sync_all()
        node1.unloadwallet(wallet_name)
        node2.unloadwallet(clone_name)
        
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
        self.test_package_mweb_parent_child()
        self.test_mweb_block_conflict_removal()
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
