#!/usr/bin/env python3
# Copyright (c) 2014-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mining RPCs for MWEB blocks"""

from decimal import Decimal

from test_framework.blocktools import (create_coinbase, NORMAL_GBT_REQUEST_PARAMS)
from test_framework.messages import (CBlock, MWEBBlock)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.ltc_util import (
    FIRST_MWEB_HEIGHT,
    create_hogex,
    get_hogex_tx,
    get_mweb_header,
)

class MWEBMiningTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.supports_cli = False

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Mine first MWEB block")
        node.generate(FIRST_MWEB_HEIGHT - 1)
        first_pegin_txid = node.sendtoaddress(node.getnewaddress(address_type='mweb'), 1)

        self.log.info("getblocktemplate: mweb rule is required for MWEB templates")
        assert_raises_rpc_error(
            -8,
            "getblocktemplate must be called with the segwit & mweb rule sets",
            node.getblocktemplate,
            {'rules': ['segwit']},
        )

        first_template = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        assert "mweb" in first_template
        assert "mweb" in first_template["rules"]

        first_mweb_block = node.generate(1)[0]
        first_hogex = get_hogex_tx(node, first_mweb_block)
        assert_equal(len(first_hogex.vin), 1)
        assert_equal(first_hogex.vin[0].prevout.hash, int(first_pegin_txid, 16))
        self.sync_all()

        # Call getblocktemplate
        node.generatetoaddress(1, node.get_deterministic_priv_key().address)
        gbt = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        next_height = int(gbt["height"])

        # Build MWEB block
        mweb_header = get_mweb_header(node)
        mweb_header.height = next_height
        mweb_header.rehash()
        mweb_block = MWEBBlock(mweb_header)

        # Build coinbase and HogEx txs
        coinbase_tx = create_coinbase(height=next_height)
        hogex_tx = create_hogex(node, mweb_header.hash)
        vtx = [coinbase_tx, hogex_tx]

        # Build block proposal
        block = CBlock()
        block.nVersion = gbt["version"]
        block.hashPrevBlock = int(gbt["previousblockhash"], 16)
        block.nTime = gbt["curtime"]
        block.nBits = int(gbt["bits"], 16)
        block.nNonce = 0
        block.vtx = vtx
        block.mweb_block = mweb_block
        block.hashMerkleRoot = block.calc_merkle_root()

        # Call getblocktemplate with the block proposal
        self.log.info("getblocktemplate: Test valid block")
        rsp = node.getblocktemplate(template_request={
            'data': block.serialize().hex(),
            'mode': 'proposal',
            'rules': ['mweb', 'segwit'],
        })
        assert_equal(rsp, None)

        self.log.info("Mine many pegins in one block")
        self.mine_many_pegins()

        self.log.info("Mine many pegouts in one block")
        self.mine_many_pegouts()

        self.log.info("Mine after MWEB mempool spend becomes stale across a reorg")
        self.mine_after_stale_mweb_spend_reorg()

    def mine_many_pegins(self):
        miner = self.nodes[1]
        funder = self.nodes[0]

        pegin_wallets = []
        pegin_funds = {}
        for i in range(8):
            miner.createwallet(wallet_name=f"pegin_batch_{i}")
            pegin_wallet = miner.get_wallet_rpc(f"pegin_batch_{i}")
            pegin_wallets.append(pegin_wallet)
            pegin_funds[pegin_wallet.getnewaddress()] = Decimal("0.2")
        funder.sendmany("", pegin_funds)
        funder.generate(1)
        self.sync_all()

        pegin_txids = []
        mweb_addr = funder.getnewaddress(address_type='mweb')
        for pegin_wallet in pegin_wallets:
            pegin_utxos = [utxo for utxo in pegin_wallet.listunspent(minconf=1) if "vout" in utxo]
            assert_equal(len(pegin_utxos), 1)
            pegin_txids.append(pegin_wallet.sendtoaddress(mweb_addr, Decimal("0.1")))

        assert_equal(set(pegin_txids).issubset(set(miner.getrawmempool())), True)

        template = miner.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        assert template["transactions"][-1]["fee"] > 0

        block_hash = miner.generate(1)[0]
        block = miner.getblock(block_hash)
        hogex = get_hogex_tx(miner, block_hash)

        assert_equal(len(hogex.vin), len(pegin_txids) + 1)
        for txid in pegin_txids:
            assert txid in block["tx"]

        self.sync_all()

    def mine_many_pegouts(self):
        funder = self.nodes[0]
        spender = self.nodes[2]

        funder.sendtoaddress(spender.getnewaddress(address_type='mweb'), 1)
        funder.generate(1)
        self.sync_all()

        pegout_txids = []
        for _ in range(6):
            pegout_txids.append(spender.sendtoaddress(funder.getnewaddress(), Decimal("0.05")))

        assert_equal(set(pegout_txids).issubset(set(spender.getrawmempool())), True)

        block_hash = spender.generate(1)[0]
        block = spender.getblock(block_hash)
        hogex = get_hogex_tx(spender, block_hash)

        assert_equal(block["tx"][-1], hogex.hash)
        assert_equal(len(hogex.vout), len(pegout_txids) + 1)
        for txid in pegout_txids:
            assert txid not in block["tx"]

        self.sync_all()

    def mine_after_stale_mweb_spend_reorg(self):
        miner = self.nodes[0]
        fork_miner = self.nodes[1]
        miner_wallet = miner.get_wallet_rpc(self.default_wallet_name)

        miner.createwallet(wallet_name="reorg_funding")
        miner.createwallet(wallet_name="reorg_stale")
        funding = miner.get_wallet_rpc("reorg_funding")
        stale_wallet = miner.get_wallet_rpc("reorg_stale")

        miner_wallet.sendtoaddress(funding.getnewaddress(), Decimal("5"))
        miner.generate(1)
        self.sync_all()

        funding_utxos = funding.listunspent(minconf=1)
        assert_equal(len(funding_utxos), 1)
        funding_utxo = funding_utxos[0]

        conflict_amount = funding_utxo["amount"] - Decimal("0.001")
        raw_conflict = miner.createrawtransaction(
            [{"txid": funding_utxo["txid"], "vout": funding_utxo["vout"]}],
            {funding.getnewaddress(): conflict_amount},
        )
        signed_conflict = funding.signrawtransactionwithwallet(raw_conflict)["hex"]
        conflict_txid = miner.decoderawtransaction(signed_conflict)["txid"]

        self.disconnect_nodes(0, 1)

        pegin_txid = funding.sendtoaddress(stale_wallet.getnewaddress(address_type='mweb'), Decimal("1"))
        pegin_tx = miner.getrawtransaction(pegin_txid, True)
        assert {"txid": funding_utxo["txid"], "vout": funding_utxo["vout"]} in [
            {"txid": vin["txid"], "vout": vin["vout"]} for vin in pegin_tx["vin"]
        ]

        pegin_block = miner.generate(1)[0]
        assert pegin_txid in miner.getblock(pegin_block)["tx"]

        stale_txid = stale_wallet.sendtoaddress(stale_wallet.getnewaddress(address_type='mweb'), Decimal("0.25"))
        assert stale_txid in miner.getrawmempool()

        fork_miner.sendrawtransaction(signed_conflict)
        fork_blocks = fork_miner.generate(2)
        assert conflict_txid in fork_miner.getblock(fork_blocks[0])["tx"]

        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert_equal(miner.getbestblockhash(), fork_blocks[-1])

        stale_remained = stale_txid in miner.getrawmempool()
        if stale_remained:
            with miner.assert_debug_log(expected_msgs=["Failed to add MWEB transaction"], timeout=10):
                miner.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        else:
            miner.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)

        mined_hash = miner.generate(1)[0]
        mined_block = miner.getblock(mined_hash)
        hogex = get_hogex_tx(miner, mined_hash)
        assert_equal(mined_block["tx"][-1], hogex.hash)


if __name__ == '__main__':
    MWEBMiningTest().main()
