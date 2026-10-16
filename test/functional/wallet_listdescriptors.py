#!/usr/bin/env python3
# Copyright (c) 2014-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the listdescriptors RPC."""

from test_framework.descriptors import (
    descsum_check,
    descsum_create,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class ListDescriptorsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    # do not create any wallet by default
    def init_wallet(self, *, node):
        return

    # Verify public and private exports use importable hardened markers and preserve address indices.
    def run_test(self):
        node = self.nodes[0]
        assert_raises_rpc_error(-18, 'No wallet is loaded.', node.listdescriptors)

        if self.is_bdb_compiled():
            self.log.info('Test that the command is not available for legacy wallets.')
            node.createwallet(wallet_name='w1', descriptors=False)
            assert_raises_rpc_error(-4, 'listdescriptors is not available for non-descriptor wallets', node.listdescriptors)

        self.log.info('Test the command for empty descriptors wallet.')
        node.createwallet(wallet_name='w2', blank=True, descriptors=True)
        assert_equal(0, len(node.get_wallet_rpc('w2').listdescriptors()['descriptors']))

        self.log.info('Test the command for a default descriptors wallet.')
        node.createwallet(wallet_name='w3', descriptors=True)
        result = node.get_wallet_rpc('w3').listdescriptors()
        assert_equal("w3", result['wallet_name'])
        assert_equal(10, len(result['descriptors']))
        assert_equal(10, len([d for d in result['descriptors'] if d['active']]))
        assert_equal(5, len([d for d in result['descriptors'] if d['internal']]))
        for item in result['descriptors']:
            assert item['desc'] != ''
            assert "'" not in item['desc']
            assert descsum_check(item['desc'])
            assert 'next' not in item
            first_index = 2 if item['desc'].startswith('mweb(') else 0
            assert item['next_index'] == first_index
            assert item['range'] == [0, first_index]
            assert item['timestamp'] is not None

        self.test_export_import(node.get_wallet_rpc('w3'))

        self.log.info('Test descriptors with hardened derivations are listed in importable form.')
        xprv = 'tprv8ZgxMBicQKsPeuVhWwi6wuMQGfPKi9Li5GtX35jVNknACgqe3CY4g5xgkfDDJcmtF7o1QnxWDRYw4H5P26PXq7sbcUkEqeR4fg3Kxp2tigg'
        xpub_acc = 'tpubDCMVLhErorrAGfApiJSJzEKwqeaf2z3NrkVMxgYQjZLzMjXMBeRw2muGNYbvaekAE8rUFLftyEar4LdrG2wXyyTJQZ26zptmeTEjPTaATts'
        hardened_path = '/84h/1h/0h'
        wallet = node.get_wallet_rpc('w2')
        wallet.importdescriptors([{
            'desc': descsum_create('wpkh(' + xprv + hardened_path.replace('h', "'") + '/0/*)'),
            'timestamp': 1296688602,
        }])
        expected = {
            'wallet_name': 'w2',
            'descriptors': [
                {'desc': descsum_create('wpkh([80002067' + hardened_path + ']' + xpub_acc + '/0/*)'),
                 'timestamp': 1296688602,
                 'active': False,
                 'range': [0, 0],
                 'next_index': 0},
            ],
        }
        assert_equal(expected, wallet.listdescriptors())
        assert_equal(expected, wallet.listdescriptors(False))

        self.log.info('Test list private descriptors')
        expected_private = {
            'wallet_name': 'w2',
            'descriptors': [
                {'desc': descsum_create('wpkh(' + xprv + hardened_path + '/0/*)'),
                 'timestamp': 1296688602,
                 'active': False,
                 'range': [0, 0],
                 'next_index': 0},
            ],
        }
        assert_equal(expected_private, wallet.listdescriptors(True))

        self.log.info("Test listdescriptors with encrypted wallet")
        wallet.encryptwallet("pass")
        assert_equal(expected, wallet.listdescriptors())

        self.log.info('Test list private descriptors with encrypted wallet')
        assert_raises_rpc_error(-13, 'Please enter the wallet passphrase with walletpassphrase first.', wallet.listdescriptors, True)
        wallet.walletpassphrase(passphrase="pass", timeout=1000000)
        assert_equal(expected_private, wallet.listdescriptors(True))

        self.log.info('Test list private descriptors with watch-only wallet')
        node.createwallet(wallet_name='watch-only', descriptors=True, disable_private_keys=True)
        watch_only_wallet = node.get_wallet_rpc('watch-only')
        watch_only_wallet.importdescriptors([{
            'desc': descsum_create('wpkh(' + xpub_acc + ')'),
            'timestamp': 1296688602,
        }])
        assert_raises_rpc_error(-4, 'Can\'t get descriptor string', watch_only_wallet.listdescriptors, True)

        self.log.info('Test non-active non-range combo descriptor')
        node.createwallet(wallet_name='w4', blank=True, descriptors=True)
        wallet = node.get_wallet_rpc('w4')
        wallet.importdescriptors([{
            'desc': descsum_create('combo(' + node.get_deterministic_priv_key().key + ')'),
            'timestamp': 1296688602,
        }])
        expected = {
            'wallet_name': 'w4',
            'descriptors': [
                {'active': False,
                 'desc': 'combo(0227d85ba011276cf25b51df6a188b75e604b38770a462b2d0e9fb2fc839ef5d3f)#np574htj',
                 'timestamp': 1296688602},
            ]
        }
        assert_equal(expected, wallet.listdescriptors())

    # Direct imports must preserve receive/change indices even after the source keypool is exhausted.
    def test_export_import(self, source):
        node = self.nodes[0]
        address_types = ('legacy', 'p2sh-segwit', 'bech32', 'bech32m', 'mweb')
        for address_type in address_types:
            for _ in range(3):
                source.getnewaddress(address_type=address_type)
                source.getrawchangeaddress(address_type=address_type)

        self.log.info('Test direct import of public and private descriptor lists, including MWEB.')
        public = source.listdescriptors()['descriptors']
        private = source.listdescriptors(True)['descriptors']
        for item in public + private:
            assert "'" not in item['desc']
            assert 'h' in item['desc'].split('#')[0]
            assert descsum_check(item['desc'])
            assert 'next' not in item
            assert item['next_index'] > (2 if item['desc'].startswith('mweb(') else 0)
            assert item['range'][0] <= item['next_index'] <= item['range'][1]

        restored_wallets = []
        for name, disable_private_keys, descriptors in (
            ('restored_public', True, public),
            ('restored_private', False, private),
        ):
            node.createwallet(wallet_name=name, blank=True, descriptors=True, disable_private_keys=disable_private_keys)
            restored = node.get_wallet_rpc(name)
            imported = restored.importdescriptors(descriptors)
            assert all(item['success'] for item in imported), imported
            assert_equal(restored.listdescriptors()['descriptors'], public)
            restored_wallets.append(restored)

        for address_type in address_types:
            expected_receive = source.getnewaddress(address_type=address_type)
            expected_change = source.getrawchangeaddress(address_type=address_type)
            for restored in restored_wallets:
                assert_equal(restored.getnewaddress(address_type=address_type), expected_receive)
                assert_equal(restored.getrawchangeaddress(address_type=address_type), expected_change)


if __name__ == '__main__':
    ListDescriptorsTest().main()
