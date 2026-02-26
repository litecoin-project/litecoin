#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Tests PSBT functionality for MWEB transactions
"""

from test_framework.ltc_util import mweb_aggregate_txs
from test_framework.messages import CTransaction, tx_from_hex
from test_framework.test_framework import LitecoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

class MWEBPsbtTest(LitecoinTestFramework):
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
        self.log.info("Setup MWEB chain")
        self.setup_mweb_chain(self.nodes[0])
        self.sync_blocks()

        # TODO: Test analyzepsbt with unfinished MWEB and finalized MWEB txs

if __name__ == '__main__':
    MWEBPsbtTest().main()
