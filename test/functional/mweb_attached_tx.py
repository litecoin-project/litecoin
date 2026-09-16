#!/usr/bin/env python3
# Copyright (c) 2026 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Uncommitted MWEB attachments must not permanently invalidate a block hash."""

import copy

from test_framework.ltc_util import setup_mweb_chain
from test_framework.messages import CBlock, CTransaction, FromHex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class MWEBAttachedTransactionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        source, victim = self.nodes
        setup_mweb_chain(source)
        self.sync_blocks()
        self.disconnect_nodes(0, 1)

        txid = source.sendtoaddress(source.getnewaddress(address_type="mweb"), 1)
        relay_tx = FromHex(CTransaction(), source.getrawtransaction(txid))
        block_hash = source.generate(1, invalid_call=False)[0]
        valid = FromHex(CBlock(), source.getblock(block_hash, 0))
        valid.vtx[0].rehash()
        valid.rehash()
        self.log.info("Reject future-height attachments to coinbase and pegin transactions")
        rejected = []
        for index in (0, 1):
            valid.vtx[index].rehash()
            mutated = copy.deepcopy(valid)
            mutated.vtx[index].mweb_tx = copy.deepcopy(relay_tx.mweb_tx)
            kernel = mutated.vtx[index].mweb_tx.body.mweb_kernels[0]
            kernel.features |= 8
            kernel.lock_height = source.getblockcount() + 100
            mutated.vtx[index].rehash()
            mutated.rehash()
            assert_equal(mutated.vtx[index].sha256, valid.vtx[index].sha256)
            assert_equal(mutated.vtx[index].calc_sha256(with_witness=True), valid.vtx[index].calc_sha256(with_witness=True))
            assert_equal(mutated.calc_merkle_root(), valid.hashMerkleRoot)
            assert_equal(mutated.sha256, valid.sha256)
            rejected.append(victim.submitblock(mutated.serialize().hex()))
        accepted = victim.submitblock(valid.serialize().hex())
        self.log.info("Mutated result: %s; honest result: %s", rejected, accepted)
        assert_equal(rejected, ["unexpected-mweb-data", "unexpected-mweb-data"])
        assert_equal(accepted, None)
        assert_equal(victim.getbestblockhash(), block_hash)


if __name__ == '__main__':
    MWEBAttachedTransactionTest().main()
