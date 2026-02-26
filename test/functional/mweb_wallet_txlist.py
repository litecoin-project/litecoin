#!/usr/bin/env python3
# Copyright (c) 2021 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test MWEB wallet transaction list display."""

import shutil
from datetime import datetime
from decimal import Decimal

from test_framework.test_framework import LitecoinTestFramework


class MWEBWalletTxListTest(LitecoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [
            ['-whitelist=noban@127.0.0.1', '-keypool=100'],
            ['-whitelist=noban@127.0.0.1', '-keypool=100'],
            ['-keypool=100'],
        ]
        self.rpc_timeout = 120

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node0, node1, node2 = self.nodes
        node0_wallet = node0.get_wallet_rpc(self.default_wallet_name)
        node1_wallet = node1.get_wallet_rpc(self.default_wallet_name)
        node2_wallet = node2.get_wallet_rpc(self.default_wallet_name)

        self.log.info("Setting up MWEB chain")
        self.setup_mweb_chain(node0)
        self.sync_all()

        self.log.info("Creating wallets")
        pegin_wallets = self.create_wallets(
            node1,
            [
                "pegin_send",
                "pegin_self",
                "pegin_offline",
            ],
        )
        pegin_pegout_wallets = self.create_wallets(
            node1,
            [
                "pegin_pegout_send",
                "pegin_pegout_self",
                "pegin_pegout_offline",
            ],
        )
        wallet_names = [self.default_wallet_name] + list(pegin_wallets.keys()) + list(pegin_pegout_wallets.keys())

        self.log.info("Snapshot wallets for no-history restore")
        self.stop_node(1)
        snapshot_names = self.snapshot_wallets(self.nodes[1], wallet_names)
        self.start_node(1, self.extra_args[1])
        self.connect_nodes(1, 0)
        self.connect_nodes(2, 1)
        self.sync_all()
        node1 = self.nodes[1]
        node1_wallet = node1.get_wallet_rpc(self.default_wallet_name)
        self.load_wallets(node1, list(pegin_wallets.keys()) + list(pegin_pegout_wallets.keys()))
        pegin_wallets = {name: node1.get_wallet_rpc(name) for name in pegin_wallets.keys()}
        pegin_pegout_wallets = {name: node1.get_wallet_rpc(name) for name in pegin_pegout_wallets.keys()}

        self.log.info("Funding wallets")
        self.fund_wallet(node0_wallet, node1_wallet, mweb_amount=Decimal("12.0"))
        for wallet in pegin_wallets.values():
            self.fund_wallet(node0_wallet, wallet, ltc_amount=Decimal("10.0"))
        for wallet in pegin_pegout_wallets.values():
            self.fund_wallet(
                node0_wallet,
                wallet,
                ltc_amount=Decimal("3.0"),
                mweb_amount=Decimal("3.0"),
            )
        self.mine_and_sync(node0)

        amounts = {
            "mweb_send": Decimal("0.5"),
            "mweb_self": Decimal("0.6"),
            "mweb_offline": Decimal("0.7"),
            "pegin_send": Decimal("1.1"),
            "pegin_self": Decimal("1.2"),
            "pegin_offline": Decimal("1.3"),
            "pegout_send": Decimal("2.1"),
            "pegout_self": Decimal("2.2"),
            "pegout_offline": Decimal("2.3"),
            "pegin_pegout_send": Decimal("3.1"),
            "pegin_pegout_self": Decimal("3.2"),
            "pegin_pegout_offline": Decimal("3.3"),
        }

        # ----------------------------------------------------------------------------
        self.log.info("MWEB->MWEB with history (send/receive)")
        mweb_send_addr = node2_wallet.getnewaddress(address_type="mweb")
        mweb_send_txid = node1_wallet.sendtoaddress(mweb_send_addr, amounts["mweb_send"])
        self.sync_mempools()
        self.assert_entry(
            node1_wallet,
            txid=mweb_send_txid,
            address=mweb_send_addr,
            amount=-amounts["mweb_send"],
            tx_type="SendToAddress",
            confirmations=0,
        )
        self.assert_entry(
            node2_wallet,
            txid=mweb_send_txid,
            address=mweb_send_addr,
            amount=amounts["mweb_send"],
            tx_type="RecvWithAddress",
            confirmations=0,
        )
        self.mine_and_sync(node0)
        self.assert_entry(
            node1_wallet,
            txid=mweb_send_txid,
            address=mweb_send_addr,
            amount=-amounts["mweb_send"],
            tx_type="SendToAddress",
            confirmations=1,
        )
        self.assert_entry(
            node2_wallet,
            txid=mweb_send_txid,
            address=mweb_send_addr,
            amount=amounts["mweb_send"],
            tx_type="RecvWithAddress",
            confirmations=1,
        )

        # ----------------------------------------------------------------------------
        self.log.info("MWEB->MWEB with history (self-send)")
        mweb_self_addr = node1_wallet.getnewaddress(address_type="mweb")
        mweb_self_txid = node1_wallet.sendtoaddress(mweb_self_addr, amounts["mweb_self"])
        self.sync_mempools()
        mweb_self_fee = node1_wallet.gettransaction(mweb_self_txid)["fee"]
        self.assert_entry(
            node1_wallet,
            txid=mweb_self_txid,
            amount=mweb_self_fee,
            tx_type="SendToSelf",
            confirmations=0,
        )
        self.mine_and_sync(node0)
        self.assert_entry(
            node1_wallet,
            txid=mweb_self_txid,
            amount=mweb_self_fee,
            tx_type="SendToSelf",
            confirmations=1,
        )

        # ----------------------------------------------------------------------------
        self.log.info("MWEB->LTC with history (send/receive)")
        pegout_send_addr = node0_wallet.getnewaddress()
        pegout_send_txid = node1_wallet.sendtoaddress(pegout_send_addr, amounts["pegout_send"])
        self.sync_mempools()
        self.assert_entry(
            node1_wallet,
            txid=pegout_send_txid,
            address=pegout_send_addr,
            amount=-amounts["pegout_send"],
            tx_type="SendToAddress",
            confirmations=0,
        )
        self.assert_entry(
            node0_wallet,
            txid=pegout_send_txid,
            address=pegout_send_addr,
            amount=amounts["pegout_send"],
            tx_type="RecvWithAddress",
            confirmations=0,
        )
        self.mine_and_sync(node0)
        self.assert_entry(
            node1_wallet,
            txid=pegout_send_txid,
            address=pegout_send_addr,
            amount=-amounts["pegout_send"],
            tx_type="SendToAddress",
            confirmations=1,
        )
        self.assert_entry(
            node0_wallet,
            txid=pegout_send_txid,
            address=pegout_send_addr,
            amount=amounts["pegout_send"],
            tx_type="RecvWithAddress",
            confirmations=1,
        )

        # ----------------------------------------------------------------------------
        self.log.info("LTC->MWEB with history (send/receive)")
        pegin_send_wallet = pegin_wallets["pegin_send"]
        pegin_send_addr = node2_wallet.getnewaddress(address_type="mweb")
        pegin_send_txid = pegin_send_wallet.sendtoaddress(pegin_send_addr, amounts["pegin_send"])
        self.sync_mempools()
        self.assert_entry(
            pegin_send_wallet,
            txid=pegin_send_txid,
            address=pegin_send_addr,
            amount=-amounts["pegin_send"],
            tx_type="SendToAddress",
            confirmations=0,
        )
        self.assert_entry(
            node2_wallet,
            txid=pegin_send_txid,
            address=pegin_send_addr,
            amount=amounts["pegin_send"],
            tx_type="RecvWithAddress",
            confirmations=0,
        )
        self.mine_and_sync(node0)
        self.assert_entry(
            pegin_send_wallet,
            txid=pegin_send_txid,
            address=pegin_send_addr,
            amount=-amounts["pegin_send"],
            tx_type="SendToAddress",
            confirmations=1,
        )
        self.assert_entry(
            node2_wallet,
            txid=pegin_send_txid,
            address=pegin_send_addr,
            amount=amounts["pegin_send"],
            tx_type="RecvWithAddress",
            confirmations=1,
        )

        # ----------------------------------------------------------------------------
        self.log.info("LTC->MWEB with history (self-send)")
        pegin_self_wallet = pegin_wallets["pegin_self"]
        pegin_self_addr = pegin_self_wallet.getnewaddress(address_type="mweb")
        pegin_self_txid = pegin_self_wallet.sendtoaddress(pegin_self_addr, amounts["pegin_self"])
        self.sync_mempools()
        pegin_self_fee = pegin_self_wallet.gettransaction(pegin_self_txid)["fee"]
        self.assert_entry(
            pegin_self_wallet,
            txid=pegin_self_txid,
            amount=pegin_self_fee,
            tx_type="SendToSelf",
            confirmations=0,
        )
        self.mine_and_sync(node0)
        self.assert_entry(
            pegin_self_wallet,
            txid=pegin_self_txid,
            amount=pegin_self_fee,
            tx_type="SendToSelf",
            confirmations=1,
        )

        # ----------------------------------------------------------------------------
        self.log.info("LTC->MWEB->LTC with history (send/receive)")
        pegin_pegout_send_wallet = pegin_pegout_wallets["pegin_pegout_send"]
        pegin_pegout_send_addr = node0_wallet.getnewaddress()
        pegin_pegout_send_txid = pegin_pegout_send_wallet.sendtoaddress(
            pegin_pegout_send_addr,
            amounts["pegin_pegout_send"],
        )
        self.sync_mempools()
        self.assert_entry(
            pegin_pegout_send_wallet,
            txid=pegin_pegout_send_txid,
            address=pegin_pegout_send_addr,
            amount=-amounts["pegin_pegout_send"],
            tx_type="SendToAddress",
            confirmations=0,
        )
        self.assert_entry(
            node0_wallet,
            txid=pegin_pegout_send_txid,
            address=pegin_pegout_send_addr,
            amount=amounts["pegin_pegout_send"],
            tx_type="RecvWithAddress",
            confirmations=0,
        )
        self.mine_and_sync(node0)
        self.assert_entry(
            pegin_pegout_send_wallet,
            txid=pegin_pegout_send_txid,
            address=pegin_pegout_send_addr,
            amount=-amounts["pegin_pegout_send"],
            tx_type="SendToAddress",
            confirmations=1,
        )
        self.assert_entry(
            node0_wallet,
            txid=pegin_pegout_send_txid,
            address=pegin_pegout_send_addr,
            amount=amounts["pegin_pegout_send"],
            tx_type="RecvWithAddress",
            confirmations=1,
        )

        # ----------------------------------------------------------------------------
        self.log.info("LTC->MWEB->LTC with history (self-send)")
        pegin_pegout_self_wallet = pegin_pegout_wallets["pegin_pegout_self"]
        pegin_pegout_self_addr = pegin_pegout_self_wallet.getnewaddress()
        pegin_pegout_self_txid = pegin_pegout_self_wallet.sendtoaddress(
            pegin_pegout_self_addr,
            amounts["pegin_pegout_self"],
        )
        self.sync_mempools()
        pegin_pegout_self_fee = pegin_pegout_self_wallet.gettransaction(pegin_pegout_self_txid)["fee"]
        self.assert_entry(
            pegin_pegout_self_wallet,
            txid=pegin_pegout_self_txid,
            amount=pegin_pegout_self_fee,
            tx_type="SendToSelf",
            confirmations=0,
        )
        self.mine_and_sync(node0)
        self.assert_entry(
            pegin_pegout_self_wallet,
            txid=pegin_pegout_self_txid,
            amount=pegin_pegout_self_fee,
            tx_type="SendToSelf",
            confirmations=1,
        )

        # ----------------------------------------------------------------------------
        self.log.info("Not seen in mempool (receiver offline)")
        offline_mweb_addr = node2_wallet.getnewaddress(address_type="mweb")
        offline_pegin_addr = node2_wallet.getnewaddress(address_type="mweb")
        offline_pegout_addr = node2_wallet.getnewaddress()
        offline_pegin_pegout_addr = node2_wallet.getnewaddress()

        self.stop_node(2)

        mweb_offline_txid = node1_wallet.sendtoaddress(offline_mweb_addr, amounts["mweb_offline"])
        self.wait_for_mempool_tx(node0, mweb_offline_txid)
        mweb_offline_block = self.mine_and_sync(node0, sync=False)
        self.sync_blocks([node0, node1])

        pegin_offline_wallet = pegin_wallets["pegin_offline"]
        pegin_offline_txid = pegin_offline_wallet.sendtoaddress(
            offline_pegin_addr,
            amounts["pegin_offline"],
        )
        self.wait_for_mempool_tx(node0, pegin_offline_txid)
        pegin_offline_block = self.mine_and_sync(node0, sync=False)
        self.sync_blocks([node0, node1])

        pegout_offline_txid = node1_wallet.sendtoaddress(offline_pegout_addr, amounts["pegout_offline"])
        self.wait_for_mempool_tx(node0, pegout_offline_txid)
        pegout_offline_block = self.mine_and_sync(node0, sync=False)
        self.sync_blocks([node0, node1])
        pegout_offline_hogex = node0.getblock(pegout_offline_block)["tx"][-1]

        pegin_pegout_offline_wallet = pegin_pegout_wallets["pegin_pegout_offline"]
        pegin_pegout_offline_txid = pegin_pegout_offline_wallet.sendtoaddress(
            offline_pegin_pegout_addr,
            amounts["pegin_pegout_offline"],
        )
        self.wait_for_mempool_tx(node0, pegin_pegout_offline_txid)
        pegin_pegout_offline_block = self.mine_and_sync(node0, sync=False)
        self.sync_blocks([node0, node1])
        pegin_pegout_offline_hogex = node0.getblock(pegin_pegout_offline_block)["tx"][-1]

        self.start_node(2, self.extra_args[2])
        self.connect_nodes(2, 0)
        self.connect_nodes(2, 1)
        node2 = self.nodes[2]
        self.sync_blocks([node0, node1, node2])
        node2_wallet = node2.get_wallet_rpc(self.default_wallet_name)

        # Offline receives can stay at 0 confirmations because only partial tx data is reconstructed.
        entry = self.wait_for_entry_confirmations(
            node2_wallet,
            min_confirmations=0,
            amount=amounts["mweb_offline"],
            tx_type="RecvWithAddress",
        )
        # Partial receive entries can still be indexed by the original txid.

        entry = self.wait_for_entry_confirmations(
            node2_wallet,
            min_confirmations=0,
            amount=amounts["pegin_offline"],
            tx_type="RecvWithAddress",
        )
        # Partial receive entries can still be indexed by the original txid.

        entry = self.wait_for_entry_confirmations(
            node2_wallet,
            min_confirmations=0,
            amount=amounts["pegout_offline"],
            tx_type="RecvWithAddress",
        )

        entry = self.wait_for_entry_confirmations(
            node2_wallet,
            min_confirmations=0,
            amount=amounts["pegin_pegout_offline"],
            tx_type="RecvWithAddress",
        )

        # ----------------------------------------------------------------------------
        self.log.info("MWEB->LTC with history (self-send)")
        pegout_self_addr = node1_wallet.getnewaddress()
        pegout_self_txid = node1_wallet.sendtoaddress(pegout_self_addr, amounts["pegout_self"])
        self.sync_mempools([node0, node1])
        pegout_self_fee = node1_wallet.gettransaction(pegout_self_txid)["fee"]
        self.assert_entry(
            node1_wallet,
            txid=pegout_self_txid,
            amount=pegout_self_fee,
            tx_type="SendToSelf",
            confirmations=0,
        )
        self.mine_and_sync(node0, sync_nodes=[node0, node1])
        self.assert_entry(
            node1_wallet,
            txid=pegout_self_txid,
            amount=pegout_self_fee,
            tx_type="SendToSelf",
            confirmations=1,
        )

        # ----------------------------------------------------------------------------
        self.log.info("Restore wallets and validate no-history behavior")
        restored_names = [snapshot_names[name] for name in wallet_names]
        restored_wallets = self.load_wallets(node1, restored_names)
        restored_wallets = {
            name: restored_wallets[snapshot_names[name]]
            for name in wallet_names
        }
        mweb_wallet = restored_wallets[self.default_wallet_name]
        pegin_wallets = {name: restored_wallets[name] for name in pegin_wallets.keys()}
        pegin_pegout_wallets = {name: restored_wallets[name] for name in pegin_pegout_wallets.keys()}
        for wallet in restored_wallets.values():
            wallet.rescanblockchain(0)

        for txid in [
            mweb_send_txid,
            mweb_self_txid,
            pegout_send_txid,
            pegout_self_txid,
            pegout_offline_txid,
        ]:
            self.assert_tx_missing(mweb_wallet, txid)

        self.assert_entry(
            pegin_wallets["pegin_send"],
            txid=pegin_send_txid,
            tx_type="SendToAddress",
        )
        self.assert_entry(
            pegin_wallets["pegin_self"],
            txid=pegin_self_txid,
            tx_type="SendToAddress",
        )
        self.assert_entry(
            pegin_wallets["pegin_offline"],
            txid=pegin_offline_txid,
            tx_type="SendToAddress",
        )

        self.assert_entry(
            pegin_pegout_wallets["pegin_pegout_send"],
            txid=pegin_pegout_send_txid,
            tx_type="SendToAddress",
        )
        self.assert_entry(
            pegin_pegout_wallets["pegin_pegout_self"],
            txid=pegin_pegout_self_txid,
            tx_type="SendToAddress",
        )
        self.assert_entry(
            pegin_pegout_wallets["pegin_pegout_offline"],
            txid=pegin_pegout_offline_txid,
            tx_type="SendToAddress",
        )

        self.print_wallets(
            [
                (0, node0),
                (1, node1),
                (2, node2),
            ]
        )

    def create_wallets(self, node, names):
        wallets = {}
        for name in names:
            node.createwallet(name)
            wallets[name] = node.get_wallet_rpc(name)
        return wallets

    def fund_wallet(self, funder, wallet, ltc_amount=None, mweb_amount=None):
        if ltc_amount is not None:
            ltc_addr = wallet.getnewaddress()
            funder.sendtoaddress(ltc_addr, ltc_amount)
        if mweb_amount is not None:
            mweb_addr = wallet.getnewaddress(address_type="mweb")
            funder.sendtoaddress(mweb_addr, mweb_amount)

    def mine_and_sync(self, node, sync=True, sync_nodes=None):
        if sync:
            if sync_nodes is None:
                return self.generate(node, 1, sync_fun=self.sync_all)[0]
            return self.generate(node, 1, sync_fun=lambda: self.sync_all(sync_nodes))[0]
        return self.generate(node, 1, sync_fun=self.no_op)[0]

    def snapshot_wallets(self, node, wallet_names, suffix="snapshot"):
        wallet_dir = node.chain_path / "wallets"
        snapshots = {}
        for name in wallet_names:
            src_name = name if name else self.wallet_data_filename
            src_path = wallet_dir / src_name
            snapshot_name = f"{name or 'default_wallet'}_{suffix}"
            dst_path = wallet_dir / snapshot_name
            if dst_path.exists():
                shutil.rmtree(dst_path)
            if src_path.is_dir():
                shutil.copytree(src_path, dst_path)
            else:
                dst_path.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_path, dst_path / self.wallet_data_filename)
            snapshots[name] = snapshot_name
        return snapshots

    def load_wallets(self, node, wallet_names):
        wallets = {}
        loaded = set(node.listwallets())
        for name in wallet_names:
            if name and name not in loaded:
                node.loadwallet(name)
            wallets[name] = node.get_wallet_rpc(name)
        return wallets

    def find_entry(self, wallet, *, txid=None, address=None, amount=None, tx_type=None, confirmations=None):
        entries = wallet.listwallettransactions()
        for entry in entries:
            if txid is not None and entry.get("txid") != txid:
                continue
            if amount is not None and entry.get("amount") != amount:
                continue
            if address is not None and entry.get("address") != address:
                continue
            if tx_type is not None and entry.get("type") != tx_type:
                continue
            if confirmations is not None and entry.get("confirmations") != confirmations:
                continue
            return entry
        return None

    def assert_entry(self, wallet, *, txid=None, address=None, amount=None, tx_type=None, confirmations=None):
        entry = self.find_entry(
            wallet,
            txid=txid,
            address=address,
            amount=amount,
            tx_type=tx_type,
            confirmations=confirmations,
        )
        if entry is None:
            raise AssertionError(
                f"Missing entry txid={txid} address={address} amount={amount} type={tx_type} confirmations={confirmations}"
            )
        return entry

    def wait_for_entry_confirmations(self, wallet, *, min_confirmations, txid=None, address=None, amount=None, tx_type=None):
        def has_confirmations():
            entry = self.find_entry(
                wallet,
                txid=txid,
                address=address,
                amount=amount,
                tx_type=tx_type,
            )
            return entry is not None and entry.get("confirmations", 0) >= min_confirmations

        self.wait_until(has_confirmations)
        return self.assert_entry(
            wallet,
            txid=txid,
            address=address,
            amount=amount,
            tx_type=tx_type,
        )

    def wait_for_mempool_tx(self, node, txid):
        self.wait_until(lambda: txid in node.getrawmempool())

    def assert_tx_missing(self, wallet, txid):
        entries = wallet.listwallettransactions()
        for entry in entries:
            if entry.get("txid") == txid:
                raise AssertionError(f"Found unexpected txid {txid}")

    def print_wallets(self, nodes):
        for node_index, node in nodes:
            wallet_names = node.listwallets()
            for name in sorted(wallet_names, key=lambda value: value or "default_wallet"):
                label = name or "default_wallet"
                print("=" * 80)
                print(f"node{node_index} - {label}")
                print("=" * 80)
                print()
                entries = node.get_wallet_rpc(name).listwallettransactions()
                for entry in entries:
                    tx_time = entry.get("blocktime", entry.get("time", entry.get("timereceived", 0)))
                    timestr = datetime.utcfromtimestamp(tx_time).strftime("%Y-%m-%d %H:%M:%S")
                    amount = entry.get("amount", Decimal("0"))
                    address = entry.get("address") or ""
                    txid = entry.get("txid", "")
                    tx_type = entry.get("type", "")
                    print(f"{timestr}: {tx_type} {amount:.8f} [{address}] {txid}")
                print()


if __name__ == '__main__':
    MWEBWalletTxListTest().main()
