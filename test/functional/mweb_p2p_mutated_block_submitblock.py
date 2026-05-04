#!/usr/bin/env python3
# Copyright (c) 2026 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify a mutated P2P MWEB block does not block later submitblock mining."""

import copy

from test_framework.ltc_util import setup_mweb_chain
from test_framework.messages import CBlock, FromHex, msg_block
from test_framework.p2p import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class MWEBP2PMutatedBlockSubmitBlockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [
            ['-whitelist=noban@127.0.0.1'],
            ['-whitelist=noban@127.0.0.1'],
            ['-whitelist=noban@127.0.0.1'],
        ]
        self.supports_cli = False

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def create_single_input_mweb_spend(self, wallet):
        return wallet.sendtoaddress(
            address=wallet.getnewaddress(address_type='mweb'),
            amount=2,
        )

    def run_test(self):
        node0, node1, node2 = self.nodes
        miner0 = node0.get_wallet_rpc(self.default_wallet_name)
        miner1 = node1.get_wallet_rpc(self.default_wallet_name)
        miner2 = node2.get_wallet_rpc(self.default_wallet_name)

        self.log.info("Setup MWEB chain")
        setup_mweb_chain(node0)
        self.sync_blocks()

        self.log.info("Create one MWEB coin per spender wallet")
        node0.createwallet(wallet_name="funder")
        node0.createwallet(wallet_name="spender0")
        node1.createwallet(wallet_name="spender1")
        funder = node0.get_wallet_rpc("funder")
        spender0 = node0.get_wallet_rpc("spender0")
        spender1 = node1.get_wallet_rpc("spender1")

        funder_addr = funder.getnewaddress(address_type="mweb")
        miner0.sendtoaddress(funder_addr, 12)
        node0.generatetoaddress(1, miner0.getnewaddress())
        self.sync_blocks()

        spender0_addr = spender0.getnewaddress(address_type="mweb")
        spender1_addr = spender1.getnewaddress(address_type="mweb")
        funder.sendtoaddress(spender0_addr, 5)
        node0.generatetoaddress(1, miner0.getnewaddress())
        self.sync_blocks()
        funder.sendtoaddress(spender1_addr, 5)
        node0.generatetoaddress(1, miner0.getnewaddress())
        self.sync_blocks()

        assert_equal(len(spender0.listunspent(addresses=[spender0_addr])), 1)
        assert_equal(len(spender1.listunspent(addresses=[spender1_addr])), 1)

        self.log.info("Create two single-input MWEB spends")
        txid0 = self.create_single_input_mweb_spend(spender0)
        txid1 = self.create_single_input_mweb_spend(spender1)
        self.sync_mempools([node0, node1, node2])

        self.log.info("Split node1 and node2 so they can mine competing chains")
        original_tip = node0.getbestblockhash()
        original_height = node0.getblockcount()
        self.disconnect_nodes(0, 1)
        self.disconnect_nodes(1, 2)

        assert_equal(set(node1.getrawmempool()), {txid0, txid1})
        assert_equal(set(node2.getrawmempool()), {txid0, txid1})

        self.log.info("Mine a valid block chain to submit later through node0's mining RPC")
        submit_hashes = node2.generatetoaddress(3, miner2.getnewaddress())
        submit_blocks = [node2.getblock(block_hash, 0) for block_hash in submit_hashes]

        self.log.info("Mine the bad-block source parent and one child on node1")
        valid_parent_hash = node1.generatetoaddress(1, miner1.getnewaddress())[0]
        valid_child_hash = node1.generatetoaddress(1, miner1.getnewaddress())[0]
        valid_parent = FromHex(CBlock(), node1.getblock(valid_parent_hash, 0))
        valid_child = FromHex(CBlock(), node1.getblock(valid_child_hash, 0))
        valid_parent.rehash()
        valid_child.rehash()
        first_submit_block = FromHex(CBlock(), submit_blocks[0])
        first_submit_block.rehash()

        assert_equal(valid_parent.hashPrevBlock, int(original_tip, 16))
        assert_equal(valid_child.hashPrevBlock, valid_parent.sha256)
        assert_equal(first_submit_block.sha256, int(submit_hashes[0], 16))
        assert_equal(first_submit_block.hashPrevBlock, int(original_tip, 16))

        self.log.info("Mutate the parent MWEB input metadata without changing its block hash")
        mutated_parent = copy.deepcopy(valid_parent)
        mutated_inputs = mutated_parent.mweb_block.body.inputs
        assert_equal(len(mutated_inputs), 2)
        assert mutated_inputs[0].commitment != mutated_inputs[1].commitment
        mutated_inputs[0].commitment, mutated_inputs[1].commitment = (
            mutated_inputs[1].commitment,
            mutated_inputs[0].commitment,
        )
        mutated_inputs[0].rehash()
        mutated_inputs[1].rehash()
        mutated_parent.rehash()
        assert_equal(mutated_parent.sha256, valid_parent.sha256)

        self.log.info("Send the mutated parent and its child to node0 over P2P")
        peer = node0.add_p2p_connection(P2PDataStore())
        with node0.assert_debug_log(expected_msgs=['mweb-connect-failed'], timeout=10):
            peer.send_message(msg_block(mutated_parent))
            peer.send_message(msg_block(valid_child))

        self.log.info("Mine several new blocks on node0 via submitblock")
        for block in submit_blocks:
            assert_equal(node0.submitblock(block), None)

        assert_equal(node0.getblockcount(), original_height + 3)
        assert_equal(node0.getbestblockhash(), submit_hashes[-1])
        assert_equal(node0.getblockhash(original_height), original_tip)


if __name__ == '__main__':
    MWEBP2PMutatedBlockSubmitBlockTest().main()
