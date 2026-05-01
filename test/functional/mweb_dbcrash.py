#!/usr/bin/env python3
# Copyright (c) 2026 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test MWEB chainstate recovery after an interrupted coins DB flush."""

import errno
import http.client
from decimal import Decimal

from test_framework.ltc_util import setup_mweb_chain
from test_framework.messages import CBlock, FromHex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class MWEBDBCrashTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.rpc_timeout = 120
        self.supports_cli = False

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def assert_flush_crashes(self, node):
        try:
            node.gettxoutsetinfo()
        except (http.client.CannotSendRequest, http.client.RemoteDisconnected):
            node.wait_until_stopped(timeout=30)
            return
        except OSError as e:
            if e.errno not in [errno.EPIPE, errno.ECONNREFUSED, errno.ECONNRESET]:
                raise
            node.wait_until_stopped(timeout=30)
            return

        raise AssertionError("Expected gettxoutsetinfo to trigger -dbcrashratio=1")

    def run_test(self):
        node = self.nodes[0]
        miner = node.get_wallet_rpc(self.default_wallet_name)

        self.log.info("Set up MWEB and create an isolated MWEB-only funding wallet")
        setup_mweb_chain(node)
        node.createwallet(wallet_name="funder", load_on_startup=True)
        node.createwallet(wallet_name="spender", load_on_startup=True)
        funder = node.get_wallet_rpc("funder")
        spender = node.get_wallet_rpc("spender")

        funder_addr = funder.getnewaddress(address_type="mweb")
        miner.sendtoaddress(funder_addr, Decimal("1.0"))
        node.generatetoaddress(1, miner.getnewaddress())
        assert_equal(len(funder.listunspent(addresses=[funder_addr])), 1)

        self.log.info("Flush the pre-crash MWEB state to make the replay window precise")
        node.gettxoutsetinfo()
        clean_tip = node.getbestblockhash()

        self.log.info("Restart with deterministic db crash simulation")
        self.restart_node(0, extra_args=["-dbbatchsize=1", "-dbcrashratio=1"])
        node = self.nodes[0]
        miner = node.get_wallet_rpc(self.default_wallet_name)
        funder = node.get_wallet_rpc("funder")
        spender = node.get_wallet_rpc("spender")
        assert_equal(node.getbestblockhash(), clean_tip)

        self.log.info("Mine a crash-window block that spends the funder's only MWEB coin")
        spender_addr = spender.getnewaddress(address_type="mweb")
        crash_txid = funder.sendtoaddress(spender_addr, Decimal("0.5"))
        assert_equal(set(node.getrawmempool()), {crash_txid})
        crash_block_hash = node.generatetoaddress(1, miner.getnewaddress())[0]
        crash_block = FromHex(CBlock(), node.getblock(crash_block_hash, 0))
        assert_equal(len(crash_block.mweb_block.body.inputs), 1)
        assert_equal(len(spender.listunspent(addresses=[spender_addr])), 1)

        self.log.info("Crash after the canonical partial batch but before MWEB state is durable")
        self.assert_flush_crashes(node)

        self.log.info("Restart and verify replay rolls MWEB state forward with the core UTXO set")
        self.start_node(0, extra_args=["-dbbatchsize=1"])
        node = self.nodes[0]
        miner = node.get_wallet_rpc(self.default_wallet_name)
        spender = node.get_wallet_rpc("spender")
        assert_equal(node.getbestblockhash(), crash_block_hash)
        assert_equal(len(spender.listunspent(addresses=[spender_addr])), 1)

        self.log.info("Spend the crash-block MWEB output; stale replay state would reject this")
        post_replay_addr = spender.getnewaddress(address_type="mweb")
        post_replay_txid = spender.sendtoaddress(post_replay_addr, Decimal("0.25"))
        assert_equal(set(node.getrawmempool()), {post_replay_txid})
        post_replay_block_hash = node.generatetoaddress(1, miner.getnewaddress())[0]
        post_replay_block = FromHex(CBlock(), node.getblock(post_replay_block_hash, 0))
        assert_equal(len(post_replay_block.mweb_block.body.inputs), 1)
        assert_equal(node.getbestblockhash(), post_replay_block_hash)


if __name__ == '__main__':
    MWEBDBCrashTest().main()
