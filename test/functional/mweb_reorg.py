#!/usr/bin/env python3
# Copyright (c) 2014-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mempool re-org scenarios for MWEB transactions

Test re-org scenarios with a mempool that contains transactions
that create or spend (directly or indirectly) MWEB outputs.
"""

from test_framework.test_framework import LitecoinTestFramework
from test_framework.util import assert_equal

class MWEBReorgTest(LitecoinTestFramework):
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
        self.basic_reorg_test()
        self.multiple_blocks_reorg_test()

    def basic_reorg_test(self):
        self.log.info("Create all pre-MWEB blocks")
        self.setup_mweb_chain(self.nodes[0])

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

    def multiple_blocks_reorg_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]

        # Make sure nodes are in sync
        self.generate(node0, 10)

        # disconnect the nodes and mine separate forks
        self.disconnect_nodes(0, 1)
        self.generate(node0, 5, sync_fun=self.no_op)
        self.generate(node1, 5, sync_fun=self.no_op)

        self.stop_nodes()
        self.start_nodes()

        # reconnect the nodes and have node0 mine 1 block, forcing a reorg on node1
        self.connect_nodes(0, 1)
        self.generate(node0, 1, sync_fun=self.sync_all)


if __name__ == '__main__':
    MWEBReorgTest().main()
