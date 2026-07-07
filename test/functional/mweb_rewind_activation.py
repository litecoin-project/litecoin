#!/usr/bin/env python3
# Copyright (c) 2026 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test flushing MWEB state rewound past the first MWEB block.

Regression test for the CoinsViewCache::Flush null-header early return:
invalidate the first MWEB block (best MWEB header -> null), restart the node
(forces FlushStateToDisk of the rewound state), then reconsider the block.
Previously, the rewound MWEB state was never flushed, so the stale on-disk
MWEB coins caused an "AddCoin: Consensus Error: DUPLICATES" exception when
reconnecting the block, and the node failed to start.
"""

from test_framework.test_framework import LitecoinTestFramework
from test_framework.util import assert_equal


class MWEBRewindActivationTest(LitecoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Activate MWEB with a pegin")
        self.setup_mweb_chain(node)
        tip_height = node.getblockcount()

        self.log.info("Find the first block carrying an MWEB header")
        first_mweb_hash = None
        first_mweb_height = 0
        for h in range(1, tip_height + 1):
            blk = node.getblock(node.getblockhash(h))
            if 'mweb' in blk:
                first_mweb_hash = blk['hash']
                first_mweb_height = h
                break
        assert first_mweb_hash is not None, "no MWEB block found"
        self.log.info(f"First MWEB block is {first_mweb_hash} at height {first_mweb_height}")

        self.log.info("Invalidate the first MWEB block (rewinds MWEB state to null header)")
        node.invalidateblock(first_mweb_hash)
        assert_equal(node.getblockcount(), first_mweb_height - 1)

        self.log.info("Restart node to force a flush of the rewound (empty) MWEB state")
        self.restart_node(0)
        assert_equal(node.getblockcount(), first_mweb_height - 1)

        self.log.info("Reconsider the block; the original chain must reconnect cleanly")
        node.reconsiderblock(first_mweb_hash)
        assert_equal(node.getblockcount(), tip_height)
        assert_equal(node.getbestblockhash(), node.getblockhash(tip_height))

        self.log.info("Restart once more and mine on top to confirm state is consistent")
        self.restart_node(0)
        self.generate(node, 1, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), tip_height + 1)


if __name__ == '__main__':
    MWEBRewindActivationTest().main()
