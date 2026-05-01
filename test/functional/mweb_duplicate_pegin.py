#!/usr/bin/env python3
# Copyright (c) 2026 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test duplicate canonical pegins for the same MWEB kernel."""

from test_framework.blocktools import (
    NORMAL_GBT_REQUEST_PARAMS,
    add_witness_commitment,
    create_coinbase,
)
from test_framework.ltc_util import create_hogex, setup_mweb_chain
from test_framework.messages import (
    COIN,
    CBlock,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    FromHex,
    MWEBBlock,
)
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


MWEB_PEGIN_OPCODE = 0x59


class MWEBDuplicatePeginTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.supports_cli = False

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    @staticmethod
    def is_mweb_pegin_script(script):
        script = bytes(script)
        return len(script) == 34 and script[0] == MWEB_PEGIN_OPCODE and script[1] == 32

    def get_template_parts(self, node, pegin_txid):
        gbt = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        assert "mweb" in gbt

        template_txs = []
        for entry in gbt["transactions"]:
            tx = FromHex(CTransaction(), entry["data"])
            tx.rehash()
            template_txs.append(tx)

        pegin_tx = next(tx for tx in template_txs if tx.hash == pegin_txid)
        hogex_tx = next(tx for tx in template_txs if tx.hogex)

        pegin_outputs = [
            (n, txout) for n, txout in enumerate(pegin_tx.vout)
            if self.is_mweb_pegin_script(txout.scriptPubKey)
        ]
        assert_equal(len(pegin_outputs), 1)

        return (
            gbt,
            FromHex(MWEBBlock(), gbt["mweb"]),
            hogex_tx.vout[0].nValue,
            pegin_outputs[0][1].nValue,
            pegin_outputs[0][1].scriptPubKey,
        )

    def create_signed_duplicate_pegin_tx(self, wallet, pegin_amount, pegin_script, duplicate_amount):
        spend_amount = pegin_amount + duplicate_amount
        fee = 10_000
        spend_utxo = next(
            utxo for utxo in wallet.listunspent()
            if utxo["spendable"]
            and not utxo.get("address", "").startswith("tmweb")
            and utxo["confirmations"] > 100
            and int(utxo["amount"] * COIN) > spend_amount + fee
        )

        change_script = CScript(bytes.fromhex(
            wallet.getaddressinfo(wallet.getrawchangeaddress())["scriptPubKey"]
        ))
        input_amount = int(spend_utxo["amount"] * COIN)

        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(spend_utxo["txid"], 16), spend_utxo["vout"]))]
        tx.vout = [
            CTxOut(pegin_amount, pegin_script),
            CTxOut(duplicate_amount, pegin_script),
            CTxOut(input_amount - spend_amount - fee, change_script),
        ]
        tx.rehash()

        signed = wallet.signrawtransactionwithwallet(tx.serialize().hex())
        assert signed["complete"]

        signed_tx = FromHex(CTransaction(), signed["hex"])
        signed_tx.rehash()
        return signed_tx

    def create_duplicate_pegin_block(self, node, gbt, mweb_block, hogex_amount, pegin_tx):
        hogex_tx = create_hogex(node, mweb_block.header.hash, amount=hogex_amount)
        hogex_tx.vin.extend([
            CTxIn(COutPoint(pegin_tx.sha256, 0)),
            CTxIn(COutPoint(pegin_tx.sha256, 1)),
        ])
        hogex_tx.rehash()

        coinbase_tx = create_coinbase(height=int(gbt["height"]))

        block = CBlock()
        block.nVersion = gbt["version"]
        block.hashPrevBlock = int(gbt["previousblockhash"], 16)
        block.nTime = gbt["curtime"]
        block.nBits = int(gbt["bits"], 16)
        block.nNonce = 0
        block.vtx = [coinbase_tx, pegin_tx, hogex_tx]
        block.mweb_block = mweb_block
        block.hashMerkleRoot = block.calc_merkle_root()

        if not pegin_tx.wit.is_null():
            add_witness_commitment(block)

        return block

    def assert_template_result(self, node, block, expected):
        assert_equal(node.getblocktemplate({
            "data": block.serialize().hex(),
            "mode": "proposal",
            "rules": ["mweb", "segwit"],
        }), expected)

    def run_test(self):
        node = self.nodes[0]
        miner = node.get_wallet_rpc(self.default_wallet_name)

        self.log.info("Activate MWEB")
        setup_mweb_chain(node)

        self.log.info("Create an LTC-only pegin source with one small confirmed coin")
        node.createwallet(wallet_name="pegin_source")
        pegin_source = node.get_wallet_rpc("pegin_source")
        miner.sendtoaddress(pegin_source.getnewaddress(address_type="legacy"), 3)
        node.generatetoaddress(1, miner.getnewaddress())

        self.log.info("Build a template containing one valid pegin")
        pegin_txid = pegin_source.sendtoaddress(
            address=pegin_source.getnewaddress(address_type="mweb"),
            amount=1,
        )
        gbt, mweb_block, hogex_amount, pegin_amount, pegin_script = self.get_template_parts(node, pegin_txid)

        self.log.info("A positive-value duplicate pegin is rejected by MWEB pegin matching")
        positive_duplicate_tx = self.create_signed_duplicate_pegin_tx(
            miner,
            pegin_amount,
            pegin_script,
            duplicate_amount=pegin_amount,
        )
        positive_duplicate_block = self.create_duplicate_pegin_block(
            node,
            gbt,
            mweb_block,
            hogex_amount,
            positive_duplicate_tx,
        )
        self.assert_template_result(node, positive_duplicate_block, "bad-blk-mweb")

        self.log.info("A zero-value duplicate pegin to the same kernel should be rejected")
        zero_duplicate_tx = self.create_signed_duplicate_pegin_tx(
            miner,
            pegin_amount,
            pegin_script,
            duplicate_amount=0,
        )
        zero_duplicate_block = self.create_duplicate_pegin_block(
            node,
            gbt,
            mweb_block,
            hogex_amount,
            zero_duplicate_tx,
        )

        self.assert_template_result(node, zero_duplicate_block, "bad-blk-mweb")


if __name__ == "__main__":
    MWEBDuplicatePeginTest().main()
