#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test LIP-0006

1. Test getdata 'mwebheader' and 'mwebleafset' before and after MWEB activation.
2. Test NODE_MWEB-gated block download across activation.
3. Test MSG_BLOCK vs MSG_MWEB_BLOCK serving.
4. Test compact block v1/v2/v3 announcements after activation.
5. Test getmwebutxos success, bounds, invalid format, and inactive-chain behavior.
"""

from test_framework.messages import (
    CBlock,
    CBlockHeader,
    CInv,
    FromHex,
    Hash,
    hash256,
    MWEB_UTXO_FORMAT_HASH_ONLY,
    MSG_BLOCK,
    MSG_MWEB_BLOCK,
    msg_getdata,
    msg_getheaders,
    msg_getmwebutxos,
    msg_headers,
    msg_sendcmpct,
    msg_sendheaders,
    MSG_MWEB_HEADER,
    MSG_MWEB_LEAFSET,
    NODE_MWEB,
    NODE_MWEB_LIGHT_CLIENT,
    NODE_NETWORK,
    NODE_WITNESS,
)
from test_framework.p2p import P2PDataStore, P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.ltc_util import FIRST_MWEB_HEIGHT, get_hogex_tx, get_mweb_header
from test_framework.util import assert_equal

MAX_MWEB_LEAFSET_DEPTH = 10
MAX_REQUESTED_MWEB_UTXOS = 4096

# Can be used to mimic a light client requesting MWEB data from a full node
class MockLightClient(P2PInterface):
    def __init__(self):
        super().__init__()
        self.blocks = {}
        self.merkle_blocks_with_mweb = {}
        self.block_headers = {}
        self.leafsets = {}
        self.mwebutxos = {}
        self.sendcmpct_versions = []

    def request_block(self, block_hash, inv_type):
        want = msg_getdata([CInv(inv_type, int(block_hash, 16))])
        self.send_message(want)

    def request_mweb_header(self, block_hash):
        want = msg_getdata([CInv(MSG_MWEB_HEADER, int(block_hash, 16))])
        self.send_message(want)

    def on_mwebheader(self, message):
        self.merkle_blocks_with_mweb[message.header_hash()] = message.merkleblockwithmweb
        
    def request_mweb_leafset(self, block_hash):
        want = msg_getdata([CInv(MSG_MWEB_LEAFSET, int(block_hash, 16))])
        self.send_message(want)

    def on_mwebleafset(self, message):
        self.leafsets[message.block_hash] = message.leafset

    def request_mweb_utxos(
            self,
            block_hash,
            start_index=0,
            num_requested=1,
            output_format=MWEB_UTXO_FORMAT_HASH_ONLY):
        self.send_message(msg_getmwebutxos(
            block_hash=Hash.from_hex(block_hash),
            start_index=start_index,
            num_requested=num_requested,
            output_format=output_format,
        ))

    def on_mwebutxos(self, message):
        self.mwebutxos[message.block_hash] = message

    def on_block(self, message):
        message.block.calc_sha256()
        block_hash = Hash(message.block.sha256)
        self.blocks[block_hash] = message.block
        self.block_headers[block_hash] = CBlockHeader(message.block)

    def on_sendcmpct(self, message):
        self.sendcmpct_versions.append(message.version)

    def wait_for_mwebutxos(self, block_hash, timeout=60):
        expected_hash = Hash.from_hex(block_hash)
        self.wait_until(lambda: expected_hash in self.mwebutxos, timeout=timeout)


class CompactMWEBPeer(P2PInterface):
    def __init__(self):
        super().__init__()
        self.last_sendcmpct = []
        self.compact_blocks = {}
        self.block_announcements = set()

    def on_sendcmpct(self, message):
        self.last_sendcmpct.append(message.version)

    def on_cmpctblock(self, message):
        message.header_and_shortids.header.calc_sha256()
        block_hash = message.header_and_shortids.header.sha256
        self.compact_blocks[block_hash] = message.header_and_shortids
        self.block_announcements.add(block_hash)

    def on_headers(self, message):
        for header in message.headers:
            header.calc_sha256()
            self.block_announcements.add(header.sha256)

    def on_inv(self, message):
        for inv in message.inv:
            if inv.type == MSG_BLOCK:
                self.block_announcements.add(inv.hash)

    def clear_announcements(self):
        with p2p_lock:
            self.compact_blocks.clear()
            self.block_announcements.clear()
            self.last_message.pop("cmpctblock", None)
            self.last_message.pop("headers", None)
            self.last_message.pop("inv", None)

    def wait_for_announcement(self, block_hash, timeout=60):
        self.wait_until(lambda: block_hash in self.block_announcements, timeout=timeout)


class MWEBBlockStorePeer(P2PDataStore):
    def __init__(self):
        super().__init__()
        self.getdata_invs = []

    def on_getdata(self, message):
        self.getdata_invs.extend(message.inv)
        super().on_getdata(message)


class MWEBP2PTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def assert_mweb_header(self, node, light_client, post_mweb_block_hash):
        assert post_mweb_block_hash in light_client.merkle_blocks_with_mweb
        merkle_block_with_mweb = light_client.merkle_blocks_with_mweb[post_mweb_block_hash]

        # Check block header is correct
        assert Hash.from_hex(post_mweb_block_hash) in light_client.block_headers
        block_header = light_client.block_headers[Hash.from_hex(post_mweb_block_hash)]
        assert_equal(block_header, merkle_block_with_mweb.merkle.header)

        # Check MWEB header is correct
        mweb_header = get_mweb_header(node, post_mweb_block_hash)
        assert_equal(mweb_header, merkle_block_with_mweb.mweb_header)

        # Check HogEx transaction is correct
        hogex_tx = get_hogex_tx(node, post_mweb_block_hash)
        assert_equal(hogex_tx, merkle_block_with_mweb.hogex)

        # Check Merkle tree
        merkle_tree = merkle_block_with_mweb.merkle.txn
        assert_equal(3, merkle_tree.nTransactions)
        assert_equal(2, len(merkle_tree.vHash))
        
        left_hash = Hash(merkle_tree.vHash[0])
        right_hash = Hash(merkle_tree.vHash[1])
        assert_equal(Hash.from_hex(hogex_tx.hash), right_hash)

        right_branch_bytes = hash256(right_hash.serialize() + right_hash.serialize())
        merkle_root_bytes = hash256(left_hash.serialize() + right_branch_bytes)
        assert_equal(Hash.from_byte_arr(merkle_root_bytes), Hash(block_header.hashMerkleRoot))

    def sync_headers_to_tip(self, node, peer):
        getheaders = msg_getheaders()
        getheaders.locator.vHave = [int(node.getbestblockhash(), 16)]
        peer.send_and_ping(getheaders)

    def add_block_to_store(self, peer, block):
        with p2p_lock:
            peer.block_store[block.sha256] = block
            peer.last_block_hash = block.sha256

    def test_mweb_download_requires_node_mweb(self, node, activation_block):
        self.log.info("Check MWEB block download is not requested from a peer without NODE_MWEB")
        no_mweb_peer = node.add_p2p_connection(
            MWEBBlockStorePeer(),
            services=NODE_NETWORK | NODE_WITNESS,
        )
        self.add_block_to_store(no_mweb_peer, activation_block)
        no_mweb_peer.send_and_ping(msg_headers([CBlockHeader(activation_block)]))
        with p2p_lock:
            assert_equal(no_mweb_peer.getdata_invs, [])

        self.log.info("Check the same MWEB block is requested from a NODE_MWEB peer")
        mweb_peer = node.add_p2p_connection(
            MWEBBlockStorePeer(),
            services=NODE_NETWORK | NODE_WITNESS | NODE_MWEB,
        )
        self.add_block_to_store(mweb_peer, activation_block)
        mweb_peer.send_message(msg_headers([CBlockHeader(activation_block)]))
        mweb_peer.wait_until(lambda: len(mweb_peer.getdata_invs) > 0, timeout=10)
        with p2p_lock:
            assert_equal(mweb_peer.getdata_invs[0].type, MSG_MWEB_BLOCK)
        self.wait_until(lambda: node.getbestblockhash() == activation_block.hash, timeout=10)

    def test_block_serving_modes(self, node, block_hash):
        self.log.info("Check MSG_BLOCK strips MWEB while MSG_MWEB_BLOCK serves full MWEB data")
        plain_peer = node.add_p2p_connection(
            MockLightClient(),
            services=NODE_NETWORK | NODE_WITNESS,
        )
        plain_peer.request_block(block_hash, MSG_BLOCK)
        plain_peer.wait_for_block(int(block_hash, 16), timeout=10)
        with p2p_lock:
            plain_block = plain_peer.blocks[Hash.from_hex(block_hash)]
            assert_equal(plain_block.mweb_block, None)
            assert not plain_block.vtx[-1].hogex

        mweb_peer = node.add_p2p_connection(
            MockLightClient(),
            services=NODE_NETWORK | NODE_WITNESS | NODE_MWEB,
        )
        mweb_peer.request_block(block_hash, MSG_MWEB_BLOCK)
        mweb_peer.wait_for_block(int(block_hash, 16), timeout=10)
        with p2p_lock:
            mweb_block = mweb_peer.blocks[Hash.from_hex(block_hash)]
            assert mweb_block.mweb_block is not None
            assert mweb_block.vtx[-1].hogex

    def test_compact_block_versions_after_mweb(self, node):
        self.log.info("Check compact block v1/v2/v3 announcements after MWEB activation")
        peers = []
        for version, services in [
            (1, NODE_NETWORK),
            (2, NODE_NETWORK | NODE_WITNESS),
            (3, NODE_NETWORK | NODE_WITNESS | NODE_MWEB),
        ]:
            peer = node.add_p2p_connection(CompactMWEBPeer(), services=services)
            peer.wait_until(lambda: len(peer.last_sendcmpct) > 0, timeout=10)
            peer.send_and_ping(msg_sendheaders())
            self.sync_headers_to_tip(node, peer)
            peer.send_and_ping(msg_sendcmpct(announce=True, version=version))
            peer.clear_announcements()
            peers.append((version, peer))

        block_hash = int(node.generate(1)[0], 16)
        for version, peer in peers:
            peer.wait_for_announcement(block_hash, timeout=10)
            with p2p_lock:
                assert block_hash in peer.compact_blocks
                compact_block = peer.compact_blocks[block_hash]
                if version == 3:
                    assert compact_block.mweb_block is not None
                else:
                    assert_equal(compact_block.mweb_block, None)

    def test_getmwebutxos(self, node, block_hash):
        self.log.info("Check getmwebutxos happy path and proof response")
        peer = node.add_p2p_connection(MockLightClient())
        peer.request_mweb_utxos(
            block_hash,
            start_index=0,
            num_requested=1,
            output_format=MWEB_UTXO_FORMAT_HASH_ONLY,
        )
        peer.wait_for_mwebutxos(block_hash, timeout=10)
        with p2p_lock:
            response = peer.mwebutxos[Hash.from_hex(block_hash)]
            assert_equal(response.block_hash, Hash.from_hex(block_hash))
            assert_equal(response.start_index, 0)
            assert_equal(response.output_format, MWEB_UTXO_FORMAT_HASH_ONLY)
            assert_equal(len(response.utxos), 1)
            assert_equal(response.utxos[0].leaf_index, 0)
            assert isinstance(response.utxos[0].output, Hash)
            assert len(response.proof_hashes) > 0

    def test_inactive_chain_requests(self, node):
        self.log.info("Check mwebleafset/getmwebutxos ignore inactive-chain blocks")
        stale_hash = node.generate(1)[0]
        node.invalidateblock(stale_hash)
        # Mine the replacement fork to a fresh address so the first block is
        # not byte-identical to the invalidated tip.
        active_hash = node.generatetoaddress(2, node.getnewaddress())[-1]
        node.reconsiderblock(stale_hash)
        assert_equal(node.getbestblockhash(), active_hash)

        peer = node.add_p2p_connection(MockLightClient())
        peer.request_mweb_leafset(stale_hash)
        peer.request_mweb_utxos(stale_hash, start_index=0, num_requested=1)
        peer.sync_with_ping(timeout=10)
        with p2p_lock:
            assert Hash.from_hex(stale_hash) not in peer.leafsets
            assert Hash.from_hex(stale_hash) not in peer.mwebutxos
            assert peer.is_connected

    def test_invalid_light_client_requests(self, node, active_mweb_hash):
        self.log.info("Check invalid getmwebutxos requests disconnect")
        invalid_format_peer = node.add_p2p_connection(MockLightClient())
        invalid_format_peer.request_mweb_utxos(active_mweb_hash, output_format=0xff)
        invalid_format_peer.wait_for_disconnect(timeout=10)

        oversized_peer = node.add_p2p_connection(MockLightClient())
        oversized_peer.request_mweb_utxos(
            active_mweb_hash,
            num_requested=MAX_REQUESTED_MWEB_UTXOS + 1,
        )
        oversized_peer.wait_for_disconnect(timeout=10)

        out_of_range_peer = node.add_p2p_connection(MockLightClient())
        out_of_range_peer.request_mweb_utxos(active_mweb_hash, start_index=1000000)
        out_of_range_peer.wait_for_disconnect(timeout=10)

    def test_depth_limit_disconnect(self, node, old_mweb_hash):
        self.log.info("Check mwebleafset depth-limit disconnect")
        while node.getblockcount() - node.getblock(old_mweb_hash)["height"] <= MAX_MWEB_LEAFSET_DEPTH:
            node.generate(1)

        peer = node.add_p2p_connection(MockLightClient())
        peer.request_mweb_leafset(old_mweb_hash)
        peer.wait_for_disconnect(timeout=10)

    def run_test(self):
        node, block_source = self.nodes
        light_client = node.add_p2p_connection(MockLightClient())

        self.log.info("Fund block source before MWEB activation")
        node.generate(101)
        self.sync_all()
        node.sendtoaddress(block_source.getnewaddress(), 25)
        node.generate(1)
        self.sync_all()

        self.log.info("Generate remaining pre-MWEB blocks")
        remaining_premweb_blocks = FIRST_MWEB_HEIGHT - 1 - node.getblockcount()
        assert remaining_premweb_blocks >= 0
        pre_mweb_block_hash = node.generate(remaining_premweb_blocks)[-1]
        self.sync_all()

        self.log.info("Request 'mwebheader' and 'mwebleafset' for pre-MWEB block '{}'".format(pre_mweb_block_hash))
        light_client.request_mweb_header(pre_mweb_block_hash)
        light_client.sync_with_ping(timeout=10)

        # Before MWEB activation, no merkle block should be returned.
        assert pre_mweb_block_hash not in light_client.merkle_blocks_with_mweb

        self.log.info("Check pre-MWEB mwebleafset request disconnects")
        pre_mweb_leafset_peer = node.add_p2p_connection(MockLightClient())
        pre_mweb_leafset_peer.request_mweb_leafset(pre_mweb_block_hash)
        pre_mweb_leafset_peer.wait_for_disconnect(timeout=10)

        self.disconnect_nodes(1, 0)

        self.log.info("Build the first MWEB block on a separate node")
        block_source.sendtoaddress(block_source.getnewaddress(address_type='mweb'), 1)
        post_mweb_block_hash = block_source.generate(1)[0]
        activation_block = FromHex(CBlock(), block_source.getblock(post_mweb_block_hash, 0))
        activation_block.rehash()

        self.test_mweb_download_requires_node_mweb(node, activation_block)

        self.log.info("Request MSG_BLOCK and MSG_MWEB_BLOCK for block '{}'".format(post_mweb_block_hash))
        self.test_block_serving_modes(node, post_mweb_block_hash)

        self.log.info("Request full block for mwebheader cross-check")
        light_client.request_block(post_mweb_block_hash, MSG_MWEB_BLOCK)
        light_client.wait_for_block(int(post_mweb_block_hash, 16), 10)
        
        self.log.info("Pegin some additional coins")
        node.sendtoaddress(node.getnewaddress(address_type='mweb'), 10)
        post_mweb_block_hash2 = node.generate(1)[0]
        light_client.wait_for_block(int(post_mweb_block_hash2, 16), 10)
        
        self.log.info("Request 'mwebheader' and 'mwebleafset' for block '{}'".format(post_mweb_block_hash))
        light_client.request_mweb_header(post_mweb_block_hash)
        light_client.request_mweb_leafset(post_mweb_block_hash)

        self.log.info("Waiting for 'mwebheader' and 'mwebleafset'")
        light_client.wait_for_mwebheader(post_mweb_block_hash, 10)
        light_client.wait_for_mwebleafset(post_mweb_block_hash, 10)

        self.log.info("Assert results")

        # After MWEB activation, the requested merkle block should be returned
        self.assert_mweb_header(node, light_client, post_mweb_block_hash)

        # After MWEB activation, the leafset should be returned
        # Only 2 outputs should be in the UTXO set (the pegin and its change)
        # That's '11' and then padded to the right with 0's, then serialized in big endian.
        # So we expect the serialized leafset to be 0b11000000 or 0xc0
        assert Hash.from_hex(post_mweb_block_hash) in light_client.leafsets
        leafset = light_client.leafsets[Hash.from_hex(post_mweb_block_hash)]
        assert_equal([0xc0], leafset)

        self.test_getmwebutxos(node, post_mweb_block_hash)
        self.test_compact_block_versions_after_mweb(node)
        self.test_inactive_chain_requests(node)
        self.test_invalid_light_client_requests(node, node.getbestblockhash())
        self.test_depth_limit_disconnect(node, post_mweb_block_hash)

        with p2p_lock:
            assert NODE_MWEB & light_client.nServices
            assert NODE_MWEB_LIGHT_CLIENT & light_client.nServices

if __name__ == '__main__':
    MWEBP2PTest().main()
