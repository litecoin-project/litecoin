#!/usr/bin/env python3
# Copyright (c) 2026 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Ensure rejected MWEB variants do not censor valid same-wtxid transactions."""

from test_framework.messages import (
    CInv,
    CTransaction,
    FromHex,
    MSG_TX,
    MSG_WTX,
    msg_inv,
    msg_tx,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.ltc_util import setup_mweb_chain


class TxPeer(P2PInterface):
    def __init__(self, serve_tx):
        super().__init__()
        self.serve_tx = serve_tx
        self.getdata_received = False

    def on_getdata(self, message):
        self.getdata_received = True
        for inv in message.inv:
            if inv.type in (MSG_TX, MSG_WTX):
                self.send_message(msg_tx(self.serve_tx))


class MWEBWtxidRecentRejectsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [
            ['-whitelist=noban@127.0.0.1'],
            ['-whitelist=noban@127.0.0.1', '-walletbroadcast=0'],
            ['-whitelist=noban@127.0.0.1', '-walletbroadcast=0'],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def assert_invalid_variants_do_not_censor(self, node, invalid_variants,
                                              honest_tx, wtxid, txid):
        for invalid_tx, reject_reason in invalid_variants:
            attacker = node.add_p2p_connection(TxPeer(invalid_tx))
            with node.assert_debug_log(expected_msgs=[reject_reason], timeout=20):
                attacker.send_message(msg_inv([CInv(MSG_WTX, wtxid)]))
                self.wait_until(lambda: attacker.getdata_received, timeout=30)
                attacker.sync_with_ping()

        honest = node.add_p2p_connection(TxPeer(honest_tx))
        honest.send_message(msg_inv([CInv(MSG_WTX, wtxid)]))
        self.wait_until(lambda: honest.getdata_received, timeout=30)
        self.wait_until(lambda: txid in node.getrawmempool(), timeout=30)

    def assert_identical_invalid_payload_is_cached(self, node, invalid_tx,
                                                   wtxid, reject_reason):
        first = node.add_p2p_connection(TxPeer(invalid_tx))
        with node.assert_debug_log(expected_msgs=[reject_reason], timeout=20):
            first.send_message(msg_inv([CInv(MSG_WTX, wtxid)]))
            self.wait_until(lambda: first.getdata_received, timeout=30)
            first.sync_with_ping()

        repeat = node.add_p2p_connection(TxPeer(invalid_tx))
        repeat.send_message(msg_inv([CInv(MSG_WTX, wtxid)]))
        repeat.sync_with_ping()
        assert not repeat.getdata_received

    def run_test(self):
        node0, node1, node2 = self.nodes

        self.log.info("Set up MWEB and fund isolated MWEB and base-coin wallets")
        setup_mweb_chain(node0)
        self.sync_all()
        node0.sendtoaddress(node1.getnewaddress(address_type='mweb'), 0.9)
        node0.sendtoaddress(node2.getnewaddress(), 1.0)
        node0.sendtoaddress(node2.getnewaddress(), 2.0)
        node0.generate(1, invalid_call=False)
        self.sync_all()

        # v24 pure MWEB IDs commit to the payload; exercise hybrid and HogEx variants.
        self.log.info("Create independent ordinary and pegin transactions")
        ordinary_txid = node2.sendtoaddress(node0.getnewaddress(), 0.2)
        ordinary_hex = node2.gettransaction(txid=ordinary_txid)['hex']
        ordinary_tx = FromHex(CTransaction(), ordinary_hex)
        assert ordinary_tx.mweb_tx is None

        pure_txid = node1.sendtoaddress(node0.getnewaddress(address_type='mweb'), 0.3)
        pure_hex = node1.gettransaction(txid=pure_txid)['hex']
        pure_tx = FromHex(CTransaction(), pure_hex)
        assert pure_tx.mweb_tx is not None
        assert len(pure_tx.vin) == 0 and len(pure_tx.vout) == 0

        # Pure MWEB IDs commit to the complete payload, so an invalid body is
        # safe to reject-cache and must not be downloaded repeatedly.
        invalid_pure_tx = FromHex(CTransaction(), pure_hex)
        invalid_pure_tx.mweb_tx.body.mweb_outputs[0].sig ^= 1
        invalid_pure_wtxid = int(invalid_pure_tx.mweb_tx.rehash(), 16)
        assert invalid_pure_wtxid != int(pure_txid, 16)

        self.log.info("An identical invalid pure-MWEB payload is requested only once")
        self.assert_identical_invalid_payload_is_cached(
            node0,
            invalid_pure_tx,
            invalid_pure_wtxid,
            "bad-mweb-txn-invalid-sig",
        )

        pegin_txid = node2.sendtoaddress(node0.getnewaddress(address_type='mweb'), 0.4)
        pegin_hex = node2.gettransaction(txid=pegin_txid)['hex']
        pegin_tx = FromHex(CTransaction(), pegin_hex)
        assert pegin_tx.mweb_tx is not None
        assert len(pegin_tx.vin) > 0 and len(pegin_tx.vout) > 0

        # A pegin whose MWEB body was stripped has the same txid/wtxid as the
        # honest pegin. It must still be recognized as an MWEB relay variant.
        stripped_pegin = FromHex(CTransaction(), pegin_hex)
        stripped_pegin.mweb_tx = None
        assert stripped_pegin.serialize() != pegin_tx.serialize()
        pegin_wtxid = pegin_tx.calc_sha256(with_witness=True)
        assert pegin_wtxid == stripped_pegin.calc_sha256(with_witness=True)

        # An invalid attached output signature is another distinct payload
        # with the same identifiers and must not poison either reject key.
        bad_signature = FromHex(CTransaction(), pegin_hex)
        bad_signature.mweb_tx.body.mweb_outputs[0].sig ^= 1
        assert bad_signature.serialize() != pegin_tx.serialize()
        assert pegin_wtxid == bad_signature.calc_sha256(with_witness=True)

        self.log.info("Invalid pegin variants must not censor the honest pegin")
        self.assert_invalid_variants_do_not_censor(
            node0,
            [
                (stripped_pegin, "pegin-count-mismatch"),
                (bad_signature, "bad-mweb-txn-invalid-sig"),
            ],
            pegin_tx,
            pegin_wtxid,
            pegin_txid,
        )

        # The HogEx marker is also excluded from txid/wtxid. Injecting it into
        # an ordinary transaction must not poison that transaction's IDs.
        marked_tx = FromHex(CTransaction(), ordinary_hex)
        marked_tx.hogex = True
        assert marked_tx.serialize() != ordinary_tx.serialize()
        ordinary_wtxid = ordinary_tx.calc_sha256(with_witness=True)
        assert ordinary_wtxid == marked_tx.calc_sha256(with_witness=True)

        self.log.info("An injected HogEx marker must not censor the honest transaction")
        self.assert_invalid_variants_do_not_censor(
            node0,
            [(marked_tx, "hogex")],
            ordinary_tx,
            ordinary_wtxid,
            ordinary_txid,
        )


if __name__ == '__main__':
    MWEBWtxidRecentRejectsTest().main()
