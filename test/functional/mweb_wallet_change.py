#!/usr/bin/env python3
# Copyright (c) 2026 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test fresh descriptor MWEB change through funding, signing, and recovery."""

from decimal import Decimal

from test_framework.test_framework import LitecoinTestFramework
from test_framework.util import assert_equal


class MWEBWalletChangeTest(LitecoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.options.descriptors = True
        self.default_wallet_name = "default_wallet"
        self.num_nodes = 2
        self.extra_args = [['-keypool=2', '-whitelist=noban@127.0.0.1']] * self.num_nodes

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def descriptors(self, wallet, private=False):
        return [item for item in wallet.listdescriptors(private)['descriptors'] if item['desc'].startswith('mweb(')]

    def import_descriptors(self, wallet, descriptors):
        requests = []
        for item in descriptors:
            request = {key: item[key] for key in ('desc', 'active', 'internal', 'range')}
            request.update(timestamp=0, next_index=item['next'])
            requests.append(request)
        results = wallet.importdescriptors(requests)
        assert all(item['success'] for item in results), results

    def next_change_index(self, wallet):
        return next(item['next'] for item in self.descriptors(wallet) if item['active'] and item['internal'])

    def coin_at(self, wallet, address):
        coins = wallet.listunspent(addresses=[address])
        assert_equal(len(coins), 1)
        return coins[0]

    def spend(self, funder, signer, source, recipient, amount, custom_change=None):
        """Fund and sign a selected input, checking automatic change ownership and transaction accounting."""
        inputs = [{'mweb_out': source['mweb_out']}] if 'mweb_out' in source else [{'txid': source['txid'], 'vout': source['vout']}]
        options = {'add_inputs': False, 'fee_rate': 10}
        if custom_change is not None:
            options['changeAddress'] = custom_change
        before = self.next_change_index(funder)
        funded = funder.walletcreatefundedpsbt(inputs, {recipient: amount}, 0, options)
        decoded = funder.decodepsbt(funded['psbt'])
        change_address = decoded['outputs'][funded['changepos']]['mweb']['address']
        if custom_change is None:
            assert funder.getaddressinfo(change_address)['ischange']
            assert signer.getaddressinfo(change_address)['ischange']
            assert change_address not in self.change_addresses
            self.change_addresses.add(change_address)
            assert self.next_change_index(funder) > before
        else:
            assert_equal(change_address, custom_change)
            assert_equal(self.next_change_index(funder), before)
            assert not funder.getaddressinfo(change_address)['ischange']
        assert int(funder.getaddressinfo(change_address)['hdkeypath'].split('/')[-1]) >= 2

        signed = signer.walletprocesspsbt(funded['psbt'])
        assert signed['complete']
        final = signer.finalizepsbt(signed['psbt'])
        assert final['complete']
        txid = signer.sendrawtransaction(final['hex'])
        self.sync_mempools()
        self.generate(self.nodes[0], 1, sync_fun=self.sync_all)
        if custom_change is None:
            transaction = signer.gettransaction(txid)
            assert_equal(transaction['amount'], -amount)
            assert all(item.get('address') != change_address for item in transaction['details'])
        return self.coin_at(signer, change_address)

    def run_test(self):
        miner = self.nodes[0]
        owner = self.nodes[1].get_wallet_rpc(self.default_wallet_name)
        self.change_addresses = set()
        self.setup_mweb_chain(miner, pegin_amount=Decimal('50'))
        self.sync_all()

        self.log.info('Locked descriptor wallets derive independent receive and change addresses')
        owner.encryptwallet('passphrase')
        receive = owner.getnewaddress(address_type='mweb')
        change = owner.getrawchangeaddress(address_type='mweb')
        assert receive != change
        assert not owner.getaddressinfo(receive)['ischange']
        assert owner.getaddressinfo(change)['ischange']
        self.change_addresses.add(change)
        initial = self.descriptors(owner)
        assert_equal(len(initial), 2)
        external = next(item for item in initial if not item['internal'])
        internal = next(item for item in initial if item['internal'])
        assert_equal(external['desc'].split(',')[0], internal['desc'].split(',')[0])
        assert external['desc'].split(',')[1] != internal['desc'].split(',')[1]

        transparent = owner.getnewaddress(address_type='bech32')
        miner.sendtoaddress(transparent, Decimal('20'))
        miner.sendtoaddress(receive, Decimal('20'))
        self.generate(miner, 1, sync_fun=self.sync_all)

        self.log.info('A locked wallet can fund MWEB change without consuming receive addresses')
        receive_next = next(item['next'] for item in self.descriptors(owner) if not item['internal'])
        source = self.coin_at(owner, transparent)
        recipient = miner.getnewaddress(address_type='mweb')
        funded = owner.walletcreatefundedpsbt([{'txid': source['txid'], 'vout': source['vout']}], {recipient: Decimal('1')})
        decoded = owner.decodepsbt(funded['psbt'])
        address = decoded['outputs'][funded['changepos']]['mweb']['address']
        assert owner.getaddressinfo(address)['ischange']
        self.change_addresses.add(address)
        assert_equal(next(item['next'] for item in self.descriptors(owner) if not item['internal']), receive_next)
        owner.walletpassphrase('passphrase', 10000)

        self.log.info('Pegins, MWEB payments, and pegouts use fresh, spendable change')
        pegin_change = self.spend(owner, owner, source, recipient, Decimal('2'))
        payment_change = self.spend(owner, owner, self.coin_at(owner, receive), recipient, Decimal('3'))
        pegout_change = self.spend(owner, owner, payment_change, miner.getnewaddress(address_type='bech32'), Decimal('1'))

        self.log.info('Watch-only funding uses the internal descriptor and the owner can sign its PSBT')
        self.nodes[1].createwallet('watch', disable_private_keys=True, blank=True, descriptors=True)
        watch = self.nodes[1].get_wallet_rpc('watch')
        self.import_descriptors(watch, self.descriptors(owner))
        watched_change = self.spend(watch, owner, pegout_change, recipient, Decimal('1'))
        assert watch.getaddressinfo(watched_change['address'])['ischange']

        self.log.info('An explicit receive address bypasses automatic change reservation')
        custom_address = owner.getnewaddress(address_type='mweb')
        self.spend(owner, owner, watched_change, recipient, Decimal('1'), custom_change=custom_address)

        self.log.info('Replacing the internal descriptor preserves the old change role')
        self.nodes[1].createwallet('replacement', descriptors=True)
        replacement = self.nodes[1].get_wallet_rpc('replacement')
        new_internal = next(item for item in self.descriptors(replacement, True) if item['internal'])
        self.import_descriptors(owner, [new_internal])
        old_internal = next(item for item in self.descriptors(owner) if item['desc'] == internal['desc'])
        assert old_internal['internal'] and not old_internal['active']
        assert owner.getaddressinfo(pegin_change['address'])['ischange']
        private = self.descriptors(owner, True)
        public = self.descriptors(owner)

        owner.unloadwallet(self.default_wallet_name)
        self.nodes[1].loadwallet(self.default_wallet_name)
        owner = self.nodes[1].get_wallet_rpc(self.default_wallet_name)
        assert owner.getaddressinfo(pegin_change['address'])['ischange']
        old_internal = next(item for item in self.descriptors(owner) if item['desc'] == internal['desc'])
        assert old_internal['internal'] and not old_internal['active']

        self.log.info('Descriptor import and rescan recover change with inactive internal descriptors')
        self.nodes[1].createwallet('restored_watch', disable_private_keys=True, blank=True, descriptors=True)
        restored_watch = self.nodes[1].get_wallet_rpc('restored_watch')
        self.import_descriptors(restored_watch, public)
        self.nodes[1].createwallet('restored', blank=True, descriptors=True)
        restored = self.nodes[1].get_wallet_rpc('restored')
        self.import_descriptors(restored, private)
        expected = {coin['mweb_out']: coin['amount'] for coin in owner.listunspent() if 'mweb_out' in coin}
        for wallet in (restored_watch, restored):
            assert_equal({coin['mweb_out']: coin['amount'] for coin in wallet.listunspent()}, expected)
            assert wallet.getaddressinfo(pegin_change['address'])['ischange']
            assert not wallet.getaddressinfo(custom_address)['ischange']
            wallet.rescanblockchain()
            assert wallet.getaddressinfo(pegin_change['address'])['ischange']
        self.log.info('Encryption keeps the selected internal descriptor active')
        imported_change = dict(next(item for item in private if item['internal'] and not item['active']), active=True)
        self.import_descriptors(replacement, [imported_change])
        selected_change = next(item['desc'] for item in self.descriptors(replacement) if item['internal'] and item['active'])
        replacement.encryptwallet('replacement-passphrase')
        assert_equal(next(item['desc'] for item in self.descriptors(replacement) if item['internal'] and item['active']), selected_change)

        self.log.info('Encrypting a restored blank wallet preserves its imported descriptors')
        active_change = next(item['desc'] for item in self.descriptors(restored) if item['internal'] and item['active'])
        restored.encryptwallet('restored-passphrase')
        assert_equal(len(restored.listdescriptors()['descriptors']), len(private))
        assert_equal(next(item['desc'] for item in self.descriptors(restored) if item['internal'] and item['active']), active_change)
        restored.walletpassphrase('restored-passphrase', 10000)
        self.spend(restored_watch, restored, pegin_change, recipient, Decimal('1'))


if __name__ == '__main__':
    MWEBWalletChangeTest().main()
