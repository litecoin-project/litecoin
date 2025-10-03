#!/usr/bin/env python3
# Test: headers pre-sync continues across peers after disconnect.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.p2p import P2PInterface
from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import CBlock, msg_headers

MAX_HEADERS_RESULTS = 2000


def _build_header_chain(genesis_hash_int, start_time, count) -> list[CBlock]:
    """
    Build `count` valid regtest blocks (headers sufficient) on top of `genesis_hash_int`.
    Returns a list of CBlock (we'll pull headers from them).
    """
    blocks = []
    prev = genesis_hash_int
    t = start_time
    for height in range(1, count + 1):
        coinbase = create_coinbase(height)
        block = create_block(prev, coinbase, t)
        block.solve()
        blocks.append(block)
        prev = block.sha256
        t += 1
    return blocks


class SharedHeaderChainPeer(P2PInterface):
    """
    A mock peer that serves headers from a shared in-memory header chain.

    Parameters:
      blocks: list of CBlock making up a contiguous chain (height 1..N)
      name: label for logs
      first_batch_only: if True, serve only the first getheaders request (<=2000 headers)
      assert_highest_locator_index: optional index (0-based in `blocks`) that must appear
                                    as the *highest* match in the inbound locator vHave.
    """
    def __init__(self, blocks: list[CBlock], name, first_batch_only=False, assert_highest_locator_height=None):
        super().__init__()
        self.blocks = blocks
        self.name = name
        #hashes: list[int] = [b.sha256 for b in blocks]
        self.hash_to_index = {b.sha256: i for i, b in enumerate(blocks)}
        self.first_batch_only = first_batch_only
        self.batches_sent = 0
        self.assert_highest_locator_height = assert_highest_locator_height

    def on_getheaders(self, message):
        vhave = list(message.locator.vHave)
        # Find the highest locator hash we recognize (vHave is ordered from best -> backoff).
        match_height = 0
        for h in vhave:
            if h in self.hash_to_index:
                match_height = self.hash_to_index[h] + 1
                break

        if self.assert_highest_locator_height is not None:
            # The node should have our 2000th header as its best-known when peer_b connects.
            expected = self.assert_highest_locator_height
            assert match_height >= expected, (
                f"{self.name}: expected locator to include our height {expected + 1} "
                f"(index {expected}), got match at index {match_height}"
            )

        start = match_height  # serve headers *after* the matched block
        stop_hash = message.hashstop
        if stop_hash != 0 and stop_hash in self.hash_to_index:
            end = self.hash_to_index[stop_hash]
        else:
            end = len(self.blocks)

        batch = self.blocks[start:min(end, start + MAX_HEADERS_RESULTS)]
        if not batch:
            return
        
        # Optionally stop answering further getheaders (used for peer_a).
        if self.first_batch_only and self.batches_sent >= 1:
            # Do nothing on subsequent getheaders; the test will disconnect us.
            return

        m = msg_headers()
        m.headers = batch
        self.send_message(m)
        self.batches_sent += 1


class HeadersPresyncReuseP2PTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        huge_min_chainwork = "0x" + "f" * 64
        self.extra_args = [[
            f"-minimumchainwork={huge_min_chainwork}",
            "-logthreadnames=1",
            "-debug=net",
        ]]

    # ---- small helpers -----------------------------------------------------

    def _only_peerinfo(self, node):
        peers = node.getpeerinfo()
        assert_equal(len(peers), 1)
        return peers[0]

    def _get_presync_height(self, node):
        """Return presync_height for the single connected peer, or -1 if absent."""
        p = self._only_peerinfo(node)
        return p.get("presynced_headers", -1)

    def _wait_for_presync_progress(self, node, min_height, timeout=30):
        def ok():
            h = self._get_presync_height(node)
            return h >= min_height
        self.wait_until(ok, timeout=timeout)

    # ---- test body ---------------------------------------------------------

    def run_test(self):
        node = self.nodes[0]

        # Build a shared chain of headers in memory: 2005 blocks is enough to cross the 2000 boundary.
        genesis_hash = int(node.getblockhash(0), 16)
        genesis_header = node.getblockheader(node.getblockhash(0))
        start_time = genesis_header["time"] + 1
        TOTAL_HEADERS = 4005
        self.log.info(f"Building {TOTAL_HEADERS} regtest headers in-memory...")
        headers_chain = _build_header_chain(genesis_hash, start_time, TOTAL_HEADERS)

        # ---------------------------------------------------------------------
        # 1) Connect peer_a and let the node pre-sync exactly 2000 headers.
        # ---------------------------------------------------------------------
        self.log.info("Connecting peer_a (serves exactly 2000 headers, then goes silent)...")
        peer_a = node.add_p2p_connection(SharedHeaderChainPeer(
            blocks=headers_chain,
            name="peer_a",
            first_batch_only=True,
        ))
        peer_a.wait_for_verack()

        # Wait until pre-sync is visible and reaches 2000.
        self.log.info("Waiting for presync_height >= 0 with peer_a...")
        self._wait_for_presync_progress(node, min_height=0, timeout=5)
        self.log.info("Waiting for presync_height >= 2000 with peer_a...")
        self._wait_for_presync_progress(node, min_height=2000, timeout=30)

        presync_height_a = self._get_presync_height(node)
        self.log.info(f"Recorded presync_height with peer_a: {presync_height_a}")
        assert presync_height_a >= 2000

        # ---------------------------------------------------------------------
        # 2) Disconnect peer_a mid pre-sync.
        # ---------------------------------------------------------------------
        self.log.info("Disconnecting peer_a mid pre-sync...")
        node.disconnect_p2ps()
        peer_a.wait_for_disconnect()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0, timeout=10)

        # ---------------------------------------------------------------------
        # 3) Connect peer_b. It should continue from height 2000 (not restart).
        #    We assert that the node's locator includes our 2000th header.
        # ---------------------------------------------------------------------
        # Index 1999 corresponds to height 2000 in `headers_chain`.
        expected_highest_locator_height = 2000

        self.log.info("Connecting peer_b (should continue pre-sync where it left off)...")
        peer_b = node.add_p2p_connection(SharedHeaderChainPeer(
            blocks=headers_chain,
            name="peer_b",
            first_batch_only=True,
            assert_highest_locator_height=expected_highest_locator_height,
        ))
        peer_b.wait_for_verack()

        # Pre-sync should re-appear on the new connection and pick up >= previous height.
        #self._wait_for_presync_progress(node, min_height=2000, timeout=3)
        self.log.info(f"Waiting for presync_height with peer_b to reach >= prior {presync_height_a}...")
        self._wait_for_presync_progress(node, min_height=presync_height_a, timeout=3)

        presync_height_b = self._get_presync_height(node)
        self.log.info(f"Final presync_height with peer_b: {presync_height_b}")
        assert presync_height_b >= presync_height_a, (
            f"Expected peer_b presync_height ({presync_height_b}) to be >= peer_a "
            f"presync_height at disconnect ({presync_height_a})"
        )

        self.log.info("SUCCESS: node continued headers pre-sync with peer_b where peer_a left off.")


if __name__ == "__main__":
    HeadersPresyncReuseP2PTest().main()
