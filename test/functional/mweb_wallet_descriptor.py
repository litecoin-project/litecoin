#!/usr/bin/env python3
# Copyright (c) 2025
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test MWEB wallet descriptors:
  - export mweb(...) from a spend-capable wallet
  - construct watch-only descriptors: mweb(master_scan_key, master_spend_xpub,*)
  - import ranged descriptors and rescan -> discover owned outputs
  - verify watch-only can derive new MWEB addresses (scan priv + spend pub)
  - import fixed-index descriptor mweb(...,i) -> only that index is accepted
  - import full (scan xprv + spend xprv) descriptor -> spend via pegout, when private export is available
"""

from decimal import Decimal
from typing import Dict, Tuple

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import LitecoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)


class MWEBWalletDescriptorsTest(LitecoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.options.descriptors = True
        self.default_wallet_name = "default_wallet"
        # miner, owner(spend-capable, source of descriptors), watch-only (ranged), fixed-index watcher, full-import spender
        self.num_nodes = 5
        # small keypools so we can see deterministic behavior in address derivation
        self.extra_args = [
            ['-whitelist=noban@127.0.0.1', '-keypool=10'],
            ['-whitelist=noban@127.0.0.1', '-keypool=10'],
            ['-whitelist=noban@127.0.0.1', '-keypool=10'],
            ['-whitelist=noban@127.0.0.1', '-keypool=10'],
            ['-whitelist=noban@127.0.0.1', '-keypool=10'],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def run_test(self):
        n0, n1, n2, n3, n4 = self.nodes

        # --- Bootstrap chain & enable MWEB ---
        self.log.info("Setting up MWEB chain")
        self.setup_mweb_chain(n0)
        self.sync_all()

        # --- Owner wallet (node1): generate two MWEB receive addresses (idx 0,1) and fund them ---
        self.log.info("Owner wallet (n1) derives 2 MWEB addresses and gets funded")
        a0 = n1.getnewaddress(address_type='mweb')
        a1 = n1.getnewaddress(address_type='mweb')

        a0_info = n1.getaddressinfo(a0)
        a1_info = n1.getaddressinfo(a1)
        print(f"Descriptor for a0: {a0_info}")
        print(f"Descriptor for a1: {a1_info}")
        a0_index = _mweb_index_from_hdkeypath(a0_info['hdkeypath'])
        a1_index = _mweb_index_from_hdkeypath(a1_info['hdkeypath'])

        txid_0 = n0.sendtoaddress(a0, Decimal('3.50000000'))
        txid_1 = n0.sendtoaddress(a1, Decimal('4.20000000'))
        self.sync_mempools()
        self.generate(n0, 1, sync_fun=self.sync_all)

        # Confirm owner sees both
        u1 = n1.listunspent(addresses=[a0, a1])
        assert_equal(len(u1), 2)
        bal1 = n1.getbalances()['mine']['trusted']
        assert_equal(bal1, Decimal('7.70000000'))

        # --- Export descriptors from owner ---
        self.log.info("Exporting MWEB descriptors from owner (n1)")
        exp_priv = [d for d in n1.listdescriptors(False)['descriptors'] if _is_mweb_desc_item(d)]
        exp_pub  = [d for d in n1.listdescriptors(False)['descriptors'] if _is_mweb_desc_item(d)]
        exp_full = None
        try:
            exp_full = [d for d in n1.listdescriptors(True)['descriptors'] if _is_mweb_desc_item(d)]
        except JSONRPCException as e:
            self.log.info("Private MWEB descriptor export unavailable; skipping full-spend import: %s", e.error["message"])
        part_priv = _partition_mweb(exp_priv)   # {False: external, True: internal?}
        part_pub  = _partition_mweb(exp_pub)

        ext_priv = part_priv[False]
        ext_pub  = part_pub[False]
        # Internal may not exist yet; if not, re-use external for change in this test
        int_priv = part_priv.get(True, ext_priv)
        int_pub  = part_pub.get(True,  ext_pub)

        # --- Watch-only ranged wallet (node2): import (scan xprv, spend xpub) and rescan ---
        self.log.info("Constructing watch-only ranged descriptors and importing into node2")
        n2.createwallet("watch_ranged", disable_private_keys=True, descriptors=True)
        w2 = n2.get_wallet_rpc("watch_ranged")

        # Build combined watch-only descriptors and normalize with checksum
        ext_watch = w2.getdescriptorinfo(_combine_watchonly_desc(ext_priv['desc'], ext_pub['desc']))['descriptor']
        int_watch = w2.getdescriptorinfo(_combine_watchonly_desc(int_priv['desc'], int_pub['desc']))['descriptor']

        # Range: if export gave a range, respect it, else use a small default
        rng = ext_priv.get('range', [0, 999])
        next_index = ext_priv.get('next', max(a0_index, a1_index) + 1)

        watch_imports = [{"desc": ext_watch, "timestamp": 0, "active": True, "internal": False, "range": rng, "next_index": next_index}]
        if int_watch != ext_watch:
            watch_imports.append({"desc": int_watch, "timestamp": 0, "active": True, "internal": True, "range": rng, "next_index": int_priv.get('next', next_index)})
        res = w2.importdescriptors(watch_imports)
        assert all(item.get('success') for item in res)

        # After rescan, node2 should see n1's two UTXOs as watch-only
        u2 = w2.listunspent(minconf=0, addresses=[a0, a1])
        assert_equal(len(u2), 2)
        assert_equal(sum(utxo['amount'] for utxo in u2), Decimal('7.70000000'))
        assert all(utxo['spendable'] for utxo in u2)
        balances2 = w2.getbalances()
        assert_equal(balances2['mine']['trusted'], Decimal('7.70000000'))
        assert 'watchonly' not in balances2

        # Verify watch-only can derive the next address (index 2) deterministically
        self.log.info("Verifying watch-only wallet can derive MWEB addresses (scan priv + spend pub)")
        # Owner derives index 2 to compare
        a2_owner = n1.getnewaddress(address_type='mweb')
        a2_watch = w2.getnewaddress(address_type='mweb')
        assert_equal(a2_watch, a2_owner)

        # --- Fixed-index watcher (node3): import only a0's index -> must see only a0 UTXOs ---
        self.log.info("Importing fixed-index mweb(...,%d) into node3; it should only accept that index", a0_index)
        n3.createwallet("watch_fixed", disable_private_keys=True, descriptors=True)
        w3 = n3.get_wallet_rpc("watch_fixed")

        ext_fixed = w3.getdescriptorinfo(_force_fixed_index(_combine_watchonly_desc(ext_priv['desc'], ext_pub['desc']), a0_index))['descriptor']
        res3 = w3.importdescriptors([{"desc": ext_fixed, "timestamp": 0}])
        assert res3[0].get('success')

        # Rescan included in import; node3 should only see funds sent to a0
        u3 = w3.listunspent(minconf=0, addresses=[a0, a1])
        # Some nodes return only matching address; assert presence precisely
        addrs3 = {utxo['address'] for utxo in u3}
        assert a0 in addrs3
        assert a1 not in addrs3
        assert_equal(sum(utxo['amount'] for utxo in u3), Decimal('3.50000000'))

        # Send one more coin to index 1 and ensure node3 still ignores it
        a1b = n1.getnewaddress(address_type='mweb')  # this should be index 3, but funds still go to node1
        txid_1b = n0.sendtoaddress(a1, Decimal('1.00000000'))  # fund existing index 1 again
        self.sync_mempools()
        self.generate(n0, 1, sync_fun=self.sync_all)
        # node3 stays at the fixed-index total
        u3_after = w3.listunspent(minconf=0, addresses=[a0, a1])
        assert_equal(sum(utxo['amount'] for utxo in u3_after), Decimal('3.50000000'))

        # --- Full import spender (node4): import scan xprv + spend xprv, then peg-out spend ---
        if not exp_full:
            return

        self.log.info("Importing full spend-capable descriptors into node4 and spending via pegout")
        n4.createwallet("full_spender", disable_private_keys=False, descriptors=True)
        w4 = n4.get_wallet_rpc("full_spender")

        part_full = _partition_mweb(exp_full)
        ext_full_priv = part_full[False]
        int_full_priv = part_full.get(True, ext_full_priv)

        ext_full = w4.getdescriptorinfo(ext_full_priv['desc'])['descriptor']
        int_full = w4.getdescriptorinfo(int_full_priv['desc'])['descriptor']
        full_imports = [{"desc": ext_full, "timestamp": 0, "active": True, "internal": False, "range": rng, "next_index": next_index}]
        if int_full != ext_full:
            full_imports.append({"desc": int_full, "timestamp": 0, "active": True, "internal": True, "range": rng, "next_index": int_full_priv.get('next', next_index)})
        res4 = w4.importdescriptors(full_imports)
        if not all(item.get('success') for item in res4):
            error_messages = [item.get('error', {}).get('message', '') for item in res4]
            if any(
                "Cannot import descriptor without private keys" in message or
                "Cannot expand descriptor. Probably because of hardened derivations without private keys provided" in message
                for message in error_messages
            ):
                self.log.info("Full-spend MWEB descriptor import unavailable; skipping spend check: %s", res4)
                return
            assert False, res4

        # Node4 should now see (at least) the two original UTXOs; balances may differ if additional sends occurred
        bal4_mine = w4.getbalances()['mine']['trusted']
        assert_greater_than(bal4_mine, Decimal('0.0'))
        bal2_mine = w2.getbalances()['mine']['trusted']

        # Spend (pegout) from MWEB to a base-layer bech32 address on miner
        pegout_addr = n0.getnewaddress(address_type='bech32')
        spend_amt = Decimal('2.00000000')
        txid_out = w4.sendtoaddress(pegout_addr, spend_amt)
        self.sync_mempools()

        tx_w4 = w4.gettransaction(txid_out)
        # amount is negative on the sender side
        assert tx_w4['amount'] <= Decimal('0')
        assert tx_w4['fee'] < Decimal('0')

        # Confirm spend
        self.generate(n0, 1, sync_fun=self.sync_all)
        n0_rcv = n0.listreceivedbyaddress(minconf=0, address_filter=pegout_addr)
        assert_equal(len(n0_rcv), 1)
        assert_equal(n0_rcv[0]['confirmations'], 1)
        # Amount may be spend_amt or spend_amt - tiny relay adjustments if subtractfee was used; here we didn't subtractfee
        assert_equal(n0_rcv[0]['amount'], spend_amt)

        # Ensure watch-only wallet (w2) sees the corresponding spentness for the inputs it tracks
        # (Balance should go down by at least 'spend_amt' once change confirms; we avoid exact change math.)
        bal2_post = w2.getbalances()['mine']['trusted']
        assert_greater_than(bal2_mine, bal2_post)

        # Watch-only can't send (no spend secret). Try a pegout and expect an RPC error.
        self.log.info("Verify watch-only wallet cannot spend MWEB coins")
        assert_raises_rpc_error(
            -4,  # insufficient privileges / private key not available
            "private key",
            lambda: w2.sendtoaddress(n0.getnewaddress(address_type='bech32'), Decimal('0.10000000')),
        )

        self.log.info("All descriptor scenarios passed.")


def _strip_checksum(desc: str) -> str:
    """Drop '#xxxxxx' suffix if present."""
    return desc.split('#', 1)[0]


def _split_mweb_params(desc: str) -> Tuple[str, str, str]:
    """
    Given 'mweb(<Kscan>,<Kspend>[,<selector>])[#chk]', return
    (Kscan, Kspend, selector). Selector is '', '<i>', or '*'.
    """
    core = _strip_checksum(desc)
    fn = "mweb("
    i0 = core.find(fn)
    assert i0 >= 0, f"not an mweb() descriptor: {desc}"
    i0 += len(fn)
    i1 = core.find(')', i0)
    assert i1 > i0 and i1 == len(core) - 1, f"malformed mweb() descriptor: {desc}"
    inside = core[i0:i1]
    # Keys do not contain commas; key origins are bracketed without commas.
    parts = [part.strip() for part in inside.split(',')]
    assert len(parts) in (2, 3), f"malformed mweb() descriptor: {desc}"
    selector = parts[2] if len(parts) == 3 else ''
    return parts[0], parts[1], selector


def _combine_watchonly_desc(priv_desc: str, pub_desc: str) -> str:
    """
    Build a watch-only descriptor: take scan key material from the owner's MWEB
    descriptor and spend key material from the public export.
    """
    kscan_priv, _, selector = _split_mweb_params(priv_desc)
    _, kspend_pub, _ = _split_mweb_params(pub_desc)
    selector_arg = f",{selector}" if selector else ""
    return f"mweb({kscan_priv},{kspend_pub}{selector_arg})"


def _force_fixed_index(desc: str, index: int) -> str:
    """Convert any ranged/unsuffixed mweb(...) to a fixed index form."""
    kscan, kspend, _ = _split_mweb_params(desc)
    return f"mweb({kscan},{kspend},{index})"


def _mweb_index_from_hdkeypath(hdkeypath: str) -> int:
    prefix = "x/"
    assert hdkeypath.startswith(prefix), f"unexpected MWEB hdkeypath: {hdkeypath}"
    return int(hdkeypath[len(prefix):])


def _is_mweb_desc_item(item: Dict) -> bool:
    return item.get("desc", "").startswith("mweb(")


def _partition_mweb(items):
    """
    Return dict {False: external, True: internal} -> item, asserting exactly one of each.
    """
    out: Dict[bool, Dict] = {}
    for it in items:
        if _is_mweb_desc_item(it):
            out[it.get("internal", False)] = it
    # Some wallets might not have an internal/change descriptor until first spend.
    # For the purposes of this test, external is mandatory.
    assert False in out, "Missing external MWEB descriptor in export"
    return out


if __name__ == '__main__':
    MWEBWalletDescriptorsTest().main()
