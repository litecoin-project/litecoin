#!/usr/bin/env python3
# Copyright (c) 2026 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Compact spent MWEB history only after block pruning, preserving proofs and retained reorgs."""

from decimal import Decimal
from pathlib import Path

from test_framework.messages import CInv, Hash, MSG_MWEB_LEAFSET, msg_getdata, msg_getmwebutxos
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.test_framework import LitecoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


class HistoryPeer(P2PInterface):
    def on_mwebleafset(self, message):
        self.leafsets[message.block_hash] = message.leafset

    def on_mwebutxos(self, message):
        self.responses[message.block_hash] = message.serialize()

    def __init__(self):
        super().__init__()
        self.responses = {}
        self.leafsets = {}

    def proof(self, block_hash):
        key = Hash.from_hex(block_hash)
        with p2p_lock:
            self.responses.pop(key, None)
            self.leafsets.pop(key, None)
        self.send_message(msg_getdata([CInv(MSG_MWEB_LEAFSET, int(block_hash, 16))]))
        self.wait_until(lambda: key in self.leafsets)
        with p2p_lock:
            leafset = self.leafsets[key]
            first = next(i for i in range(8 * len(leafset)) if leafset[i // 8] & (0x80 >> (i % 8)))
        self.send_message(msg_getmwebutxos(block_hash=key, start_index=first, num_requested=4096))
        self.wait_until(lambda: key in self.responses)
        with p2p_lock:
            return leafset, self.responses[key]


class MWEBSpentHistoryTest(LitecoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-fastprune=1"]]
        self.rpc_timeout = 120

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        """Prune old spends twice, comparing proofs and exercising restart, undo and subsequent spending."""
        node = self.nodes[0]
        self.setup_mweb_chain(node, pegin_amount=Decimal("10"))
        miner = node.get_wallet_rpc(self.default_wallet_name)
        node.createwallet("sender", load_on_startup=True)
        sender = node.get_wallet_rpc("sender")
        miner.sendtoaddress(sender.getnewaddress(address_type="mweb"), Decimal("5"))
        self.generate(node, 1, sync_fun=self.no_op)

        def spend_all():
            sender.sendtoaddress(address=sender.getnewaddress(address_type="mweb"), amount=sender.getbalance(), subtractfeefromamount=True)
            return self.generate(node, 1, sync_fun=self.no_op)[0]

        self.log.info("Build spent history and retain a spend just below the tip")
        for _ in range(8):
            spend_all()
        old_height = node.getblockcount()
        self.generate(node, 400, sync_fun=self.no_op)
        previous = node.getbestblockhash()
        tip = spend_all()
        node.gettxoutsetinfo()
        directory = Path(node.chain_path)
        assert_equal(list(directory.glob("prun*.dat")), [])
        before_size = sum(path.stat().st_size for path in directory.glob("O*.dat"))
        balance = sender.getbalance()
        peer = node.add_p2p_connection(HistoryPeer())
        proofs = {block: peer.proof(block) for block in [previous, tip]}

        self.log.info("Manual block pruning publishes a smaller MWEB hash file and preserves both recent proofs")
        self.restart_node(0, extra_args=["-fastprune=1", "-prune=1"])
        node = self.nodes[0]
        sender = node.get_wallet_rpc("sender")
        node.pruneblockchain(node.getblockcount() - 288)
        node.gettxoutsetinfo()
        assert_greater_than(node.getblockchaininfo()["pruneheight"], old_height)
        prune_files = list(directory.glob("prun*.dat"))
        assert_equal(len(prune_files), 1)
        assert any(prune_files[0].read_bytes())
        after_size = sum(path.stat().st_size for path in directory.glob("O*.dat"))
        assert_greater_than(before_size, after_size)
        peer = node.add_p2p_connection(HistoryPeer())
        for block, proof in proofs.items():
            assert_equal(peer.proof(block), proof)
        assert_equal(sender.getbalance(), balance)

        self.log.info("Restart the compacted chainstate and disconnect/reconnect the retained spend")
        self.restart_node(0, extra_args=["-fastprune=1", "-prune=1"])
        node = self.nodes[0]
        sender = node.get_wallet_rpc("sender")
        peer = node.add_p2p_connection(HistoryPeer())
        assert_equal(peer.proof(tip), proofs[tip])
        node.invalidateblock(tip)
        assert_equal(node.getbestblockhash(), previous)
        node.gettxoutsetinfo()
        assert_equal(peer.proof(previous), proofs[previous])
        node.reconsiderblock(tip)
        assert_equal(node.getbestblockhash(), tip)
        assert_equal(peer.proof(tip), proofs[tip])

        self.log.info("Advance the pruning horizon and replace its prune list, then spend after another restart")
        self.generate(node, 400, sync_fun=self.no_op)
        node.pruneblockchain(node.getblockcount() - 288)
        node.gettxoutsetinfo()
        updated_files = list(directory.glob("prun*.dat"))
        assert_equal(len(updated_files), 1)
        assert updated_files[0] != prune_files[0]
        tip = node.getbestblockhash()
        proof = peer.proof(tip)
        self.restart_node(0, extra_args=["-fastprune=1", "-prune=1"])
        node = self.nodes[0]
        sender = node.get_wallet_rpc("sender")
        peer = node.add_p2p_connection(HistoryPeer())
        assert_equal(peer.proof(tip), proof)
        assert_equal(sender.getbalance(), balance)
        spend_all()
        assert_equal(node.getrawmempool(), [])


if __name__ == "__main__":
    MWEBSpentHistoryTest().main()
