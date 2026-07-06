#!/usr/bin/env python3
# Copyright (c) 2026 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that headers pre-sync continues across peers after disconnect."""

from test_framework.blocktools import (
    create_block,
    create_coinbase,
)
from test_framework.messages import (
    msg_headers,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

MAX_HEADERS_RESULTS = 2000


def build_header_chain(genesis_hash_int, start_time, count):
    blocks = []
    prev_hash = genesis_hash_int
    time = start_time
    for height in range(1, count + 1):
        coinbase = create_coinbase(height)
        block = create_block(prev_hash, coinbase, time)
        block.solve()
        blocks.append(block)
        prev_hash = block.sha256
        time += 1
    return blocks


class SharedHeaderChainPeer(P2PInterface):
    """A mock peer that serves headers from a shared in-memory header chain."""

    def __init__(self, blocks, name, first_batch_only=False, assert_highest_locator_height=None):
        super().__init__()
        self.blocks = blocks
        self.name = name
        self.hash_to_index = {block.sha256: index for index, block in enumerate(blocks)}
        self.first_batch_only = first_batch_only
        self.batches_sent = 0
        self.assert_highest_locator_height = assert_highest_locator_height

    def on_getheaders(self, message):
        match_height = 0
        for locator_hash in message.locator.vHave:
            if locator_hash in self.hash_to_index:
                match_height = self.hash_to_index[locator_hash] + 1
                break

        if self.assert_highest_locator_height is not None:
            assert match_height >= self.assert_highest_locator_height, (
                f"{self.name}: expected locator to include height "
                f"{self.assert_highest_locator_height}, got {match_height}"
            )

        start = match_height
        stop_hash = message.hashstop
        if stop_hash != 0 and stop_hash in self.hash_to_index:
            end = self.hash_to_index[stop_hash]
        else:
            end = len(self.blocks)

        batch = self.blocks[start:min(end, start + MAX_HEADERS_RESULTS)]
        if not batch:
            return

        if self.first_batch_only and self.batches_sent >= 1:
            return

        self.send_message(msg_headers(headers=batch))
        self.batches_sent += 1


class HeadersPresyncReuseP2PTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        huge_min_chainwork = "0x" + "f" * 64
        self.extra_args = [[
            f"-minimumchainwork={huge_min_chainwork}",
            "-debug=net",
        ]]

    def get_only_peerinfo(self):
        peers = self.nodes[0].getpeerinfo()
        assert_equal(len(peers), 1)
        return peers[0]

    def get_presync_height(self):
        return self.get_only_peerinfo().get("presynced_headers", -1)

    def wait_for_presync_progress(self, min_height, timeout=30):
        self.wait_until(lambda: self.get_presync_height() >= min_height, timeout=timeout)

    def run_test(self):
        node = self.nodes[0]

        genesis_hash = int(node.getblockhash(0), 16)
        genesis_header = node.getblockheader(node.getblockhash(0))
        total_headers = 4005
        self.log.info("Building %d regtest headers in memory", total_headers)
        headers_chain = build_header_chain(genesis_hash, genesis_header["time"] + 1, total_headers)

        self.log.info("Connecting peer_a")
        peer_a = node.add_p2p_connection(SharedHeaderChainPeer(
            blocks=headers_chain,
            name="peer_a",
            first_batch_only=True,
        ))
        peer_a.wait_for_verack()

        self.wait_for_presync_progress(min_height=2000)
        presync_height_a = self.get_presync_height()
        assert presync_height_a >= 2000

        self.log.info("Disconnecting peer_a mid pre-sync")
        node.disconnect_p2ps()
        peer_a.wait_for_disconnect()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)

        self.log.info("Connecting peer_b")
        peer_b = node.add_p2p_connection(SharedHeaderChainPeer(
            blocks=headers_chain,
            name="peer_b",
            first_batch_only=True,
            assert_highest_locator_height=2000,
        ))
        peer_b.wait_for_verack()

        self.wait_for_presync_progress(min_height=presync_height_a, timeout=3)
        assert self.get_presync_height() >= presync_height_a


if __name__ == "__main__":
    HeadersPresyncReuseP2PTest().main()
