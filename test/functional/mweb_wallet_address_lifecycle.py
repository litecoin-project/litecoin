#!/usr/bin/env python3
# Copyright (c) 2026 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test MWEB address generation across wallet and keypool lifecycles."""

from test_framework.test_framework import LitecoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class MWEBWalletAddressLifecycleTest(LitecoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [['-keypool=2']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        self.test_blank_wallet(node)
        self.test_private_keys_disabled_wallet(node)
        self.test_mweb_keypool_policy(node)

    def assert_no_addresses(self, wallet):
        assert_raises_rpc_error(
            -4,
            "Error: This wallet has no available keys",
            wallet.getnewaddress,
            address_type='mweb',
        )
        assert_raises_rpc_error(
            -4,
            "Error: This wallet has no available keys",
            wallet.getrawchangeaddress,
            address_type='mweb',
        )

    def reload_wallet(self, node, wallet_name):
        node.get_wallet_rpc(wallet_name).unloadwallet()
        node.loadwallet(wallet_name)
        return node.get_wallet_rpc(wallet_name)

    def test_blank_wallet(self, node):
        self.log.info("Blank wallets do not invent MWEB keys")
        wallet_name = 'mweb_blank'
        node.createwallet(wallet_name=wallet_name, blank=True)
        wallet = node.get_wallet_rpc(wallet_name)

        assert wallet.getwalletinfo()['private_keys_enabled']
        self.assert_no_addresses(wallet)
        assert_raises_rpc_error(-4, "Error refreshing keypool", wallet.keypoolrefill, 2)

        self.log.info("Blank-wallet behavior survives reload")
        wallet = self.reload_wallet(node, wallet_name)
        self.assert_no_addresses(wallet)

        if not self.options.descriptors:
            self.log.info("Setting an HD seed activates MWEB addresses in a blank legacy wallet")
            wallet.sethdseed()
            address = wallet.getnewaddress(address_type='mweb')
            assert_equal(wallet.getaddressinfo(address)['ismine'], True)

    def test_private_keys_disabled_wallet(self, node):
        self.log.info("Private-keys-disabled wallets start without MWEB keys")
        wallet_name = 'mweb_private_keys_disabled'
        node.createwallet(wallet_name=wallet_name, disable_private_keys=True)
        wallet = node.get_wallet_rpc(wallet_name)

        assert_equal(wallet.getwalletinfo()['private_keys_enabled'], False)
        self.assert_no_addresses(wallet)

        self.log.info("Private-keys-disabled behavior survives reload")
        wallet = self.reload_wallet(node, wallet_name)
        assert_equal(wallet.getwalletinfo()['private_keys_enabled'], False)
        self.assert_no_addresses(wallet)

    def test_mweb_keypool_policy(self, node):
        self.log.info("Test MWEB address generation while an encrypted wallet is locked")
        wallet_name = 'mweb_keypool'
        passphrase = 'mweb-keypool-passphrase'
        node.createwallet(wallet_name=wallet_name, passphrase=passphrase)
        wallet = node.get_wallet_rpc(wallet_name)

        if self.options.descriptors:
            self.log.info("Descriptor wallets extend MWEB addresses from cached public derivation data")
            addresses = {
                wallet.getnewaddress(address_type='mweb'),
                wallet.getrawchangeaddress(address_type='mweb'),
                wallet.getnewaddress(address_type='mweb'),
                wallet.getrawchangeaddress(address_type='mweb'),
                wallet.getnewaddress(address_type='mweb'),
            }
            assert_equal(len(addresses), 5)

            wallet = self.reload_wallet(node, wallet_name)
            next_address = wallet.getnewaddress(address_type='mweb')
            assert next_address not in addresses
            return

        self.log.info("Legacy receive and change addresses share a dedicated MWEB keypool")
        first_addresses = {
            wallet.getnewaddress(address_type='mweb'),
            wallet.getrawchangeaddress(address_type='mweb'),
        }
        assert_equal(len(first_addresses), 2)
        assert_raises_rpc_error(
            -12,
            "Error: Keypool ran out, please call keypoolrefill first",
            wallet.getnewaddress,
            address_type='mweb',
        )

        self.log.info("MWEB keypool exhaustion survives reload")
        wallet = self.reload_wallet(node, wallet_name)
        assert_raises_rpc_error(
            -12,
            "Error: Keypool ran out, please call keypoolrefill first",
            wallet.getnewaddress,
            address_type='mweb',
        )

        self.log.info("Exhausting MWEB keys does not consume the ordinary external keypool")
        wallet.getnewaddress(address_type='bech32')
        wallet.getnewaddress(address_type='bech32')

        assert_raises_rpc_error(-13, "wallet passphrase", wallet.keypoolrefill, 2)
        wallet.walletpassphrase(passphrase, 60)
        wallet.keypoolrefill(2)
        wallet.walletlock()

        refilled_addresses = {wallet.getrawchangeaddress(address_type='mweb')}
        wallet = self.reload_wallet(node, wallet_name)
        refilled_addresses.add(wallet.getnewaddress(address_type='mweb'))
        assert_equal(len(refilled_addresses), 2)
        assert first_addresses.isdisjoint(refilled_addresses)
        assert_raises_rpc_error(
            -12,
            "Error: Keypool ran out, please call keypoolrefill first",
            wallet.getrawchangeaddress,
            address_type='mweb',
        )


if __name__ == '__main__':
    MWEBWalletAddressLifecycleTest().main()
