#!/usr/bin/env python3
# Copyright (c) 2021-2024 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test watchonly "View keys" for MWEB addresses.
"""

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import LitecoinTestFramework
from test_framework.util import assert_equal


class MwebWatchOnlyTest(LitecoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Setting up MWEB chain")
        self.setup_mweb_chain(node)

        def_wallet = node.get_wallet_rpc(self.default_wallet_name)
        watch_mweb_addr = def_wallet.getnewaddress(address_type='mweb')

        node.createwallet(wallet_name='watch_wallet', disable_private_keys=True)
        watch_wallet = node.get_wallet_rpc('watch_wallet')

        subaddr_descriptor = def_wallet.getaddressinfo(watch_mweb_addr)['desc']
        print(subaddr_descriptor)
        res = watch_wallet.importdescriptors([
            {"desc": subaddr_descriptor, "timestamp": 0, "active": False,  "internal": False},
        ])
        print(res)
        assert all(item.get('success') for item in res)

        print(watch_wallet.getaddressinfo(watch_mweb_addr))
        self.log.info('Imported MWEB watch-only descriptor should not match sibling MWEB outputs')
        assert_equal(watch_wallet.getbalance(), 0)
        assert_equal(len(watch_wallet.listtransactions()), 0)

        # send 1 ltc to our watch-only address
        txid = def_wallet.sendtoaddress(watch_mweb_addr, 1)
        self.generate(node, 1)

        # getbalance
        self.log.info('include_watchonly should default to true for watch-only wallets')
        self.log.info('Testing getbalance watch-only defaults')
        assert_equal(watch_wallet.getbalance(), 1)
        assert_equal(len(watch_wallet.listtransactions()), 1)


if __name__ == '__main__':
    MwebWatchOnlyTest().main()
