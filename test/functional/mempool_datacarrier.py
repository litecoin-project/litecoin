#!/usr/bin/env python3
# Copyright (c) 2020-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test aggregate main-chain datacarrier policy, configuration, relay and mining."""
from typing import List, Optional

from test_framework.messages import (
    CTxOut,
    MAX_OP_RETURN_RELAY,
)
from test_framework.script import (
    CScript,
    OP_RETURN,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    random_bytes,
)
from test_framework.wallet import MiniWallet


class DataCarrierTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.extra_args = [
            [],
            ["-datacarrier=0"],
            ["-datacarrier=1", "-datacarriersize=83"],
            ["-datacarriersize=0", "-permitbaremultisig=0"],
        ]

    # Complete OP_RETURN scripts share one budget; successful transactions must enter the mempool.
    def test_null_data_transaction(self, node: TestNode, data: List[Optional[bytes]], success: bool, reject_reason="datacarrier") -> str:
        tx = self.wallet.create_self_transfer(fee_rate=0)["tx"]
        for payload in data:
            script = CScript([OP_RETURN] if payload is None else [OP_RETURN, payload])
            tx.vout.append(CTxOut(nValue=0, scriptPubKey=script))
        tx.vout[0].nValue -= tx.get_vsize()  # Pay 1 litoshi/vbyte.

        tx_hex = tx.serialize().hex()
        txid = tx.rehash()
        result = node.testmempoolaccept([tx_hex])[0]
        assert_equal(result["allowed"], success)

        if success:
            self.wallet.sendrawtransaction(from_node=node, tx_hex=tx_hex)
            assert txid in node.getrawmempool()
        else:
            assert_equal(result["reject-reason"], reject_reason)
            assert_raises_rpc_error(-26, reject_reason, self.wallet.sendrawtransaction, from_node=node, tx_hex=tx_hex)
        return txid

    # Defaults admit large and multiple carriers, custom budgets count script opcodes, and admitted data relays and mines.
    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.wallet.rescan_utxos()

        for node, limit, bare_multisig in zip(self.nodes, [MAX_OP_RETURN_RELAY, 0, 83, 0], [True, True, True, False]):
            info = node.getmempoolinfo()
            assert_equal(info["maxdatacarriersize"], limit)
            assert_equal(info["permitbaremultisig"], bare_multisig)

        self.log.info("Testing large and multiple data carriers with the default policy.")
        mined_txids = []
        for data in [[random_bytes(80)], [random_bytes(81)], [random_bytes(1_000)],
                     [random_bytes(40), random_bytes(40)], [None, None], [random_bytes(99_000)]]:
            mined_txids.append(self.test_null_data_transaction(self.nodes[0], data, True))
        self.test_null_data_transaction(self.nodes[0], [random_bytes(100_000)], False, "tx-size")

        self.log.info("Testing disabled data carriers, including bare OP_RETURN and empty pushes.")
        for node in [self.nodes[1], self.nodes[3]]:
            for data in [[None], [b""], [random_bytes(80)], [None, None]]:
                self.test_null_data_transaction(node, data, False)

        self.log.info("Testing an 83-byte aggregate budget, including script opcodes but excluding output overhead.")
        for data, success in [([random_bytes(80)], True), ([random_bytes(81)], False),
                              ([random_bytes(40), random_bytes(39)], True),
                              ([random_bytes(40), random_bytes(40)], False),
                              ([random_bytes(80), None], False), ([None, None], True)]:
            self.test_null_data_transaction(self.nodes[2], data, success)

        self.log.info("Testing relay between nodes with the default policy.")
        self.restart_node(3, extra_args=[])
        self.connect_nodes(0, 3)
        assert_equal(self.nodes[3].getmempoolinfo()["maxdatacarriersize"], MAX_OP_RETURN_RELAY)
        txid = self.test_null_data_transaction(self.nodes[0], [random_bytes(1_000), random_bytes(2_000)], True)
        self.wait_until(lambda: txid in self.nodes[3].getrawmempool())
        mined_txids.append(txid)

        self.log.info("Testing mining eligibility for large and multiple data carriers.")
        blockhash = self.generate(self.nodes[0], 1, sync_fun=self.sync_blocks)[0]
        block_txids = self.nodes[0].getblock(blockhash)["tx"]
        for txid in mined_txids:
            assert txid in block_txids


if __name__ == '__main__':
    DataCarrierTest().main()
