#!/usr/bin/env python3
# Copyright (c) 2018-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import time

from test_framework.test_framework import LitecoinTestFramework

from test_framework.util import (
    assert_equal,
)

class MWEBNodeCompatibilityTest(LitecoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.wallet_names = [self.default_wallet_name]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_previous_releases()

    def setup_nodes(self):
        versions = [None, None, 180100]
        self.add_nodes(len(versions), versions=versions)
        self.start_nodes()
        self.import_deterministic_coinbase_privkeys()

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.connect_nodes(0, 2)
        self.connect_nodes(1, 2)

    def run_test(self):
        node_a_master = self.nodes[0]
        node_b_master = self.nodes[1]
        node_c_v18 = self.nodes[2]

        self.setup_mweb_chain(node_a_master)
        self.sync_all()

        a_chain_info = node_a_master.getblockchaininfo()
        b_chain_info = node_b_master.getblockchaininfo()
        c_chain_info = node_c_v18.getblockchaininfo()
        assert_equal(int(b_chain_info['blocks']), int(a_chain_info['blocks']))
        assert_equal(int(c_chain_info['blocks']), int(a_chain_info['blocks']))

        self.disconnect_nodes(0, 1)

        mweb_addr = node_a_master.getnewaddress(address_type='mweb')
        pegin_txid = node_a_master.sendtoaddress(mweb_addr, 100)

        # Synchronization can be slow when this runs in parallel with the full test suite.
        self.sync_mempools([node_a_master, node_c_v18], wait=0.1, timeout=60)
        assert_equal(set(node_a_master.getrawmempool()), {pegin_txid})
        assert_equal(set(node_c_v18.getrawmempool()), {pegin_txid})

        # Keep checking for a relay interval window. If node_b ever accepts the tx,
        # the predicate records that and the wait will time out.
        relay_window_s = 10
        start_time = time.time()
        saw_on_node_b = False

        def node_b_rejected_pegin():
            nonlocal saw_on_node_b
            saw_on_node_b = saw_on_node_b or pegin_txid in node_b_master.getrawmempool()
            return not saw_on_node_b and (time.time() - start_time) >= relay_window_s

        self.wait_until(node_b_rejected_pegin, timeout=relay_window_s + 5)
        assert_equal(set(node_b_master.getrawmempool()), set())

if __name__ == '__main__':
    MWEBNodeCompatibilityTest().main()
