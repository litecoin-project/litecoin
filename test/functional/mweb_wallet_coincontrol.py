#!/usr/bin/env python3
# Copyright (c) 2026 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test wallet RPC coin control with MWEB outputs."""

from decimal import Decimal

from test_framework.test_framework import LitecoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class MWEBWalletCoinControlTest(LitecoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [
            ['-whitelist=noban@127.0.0.1'],
            ['-whitelist=noban@127.0.0.1'],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        funding_node = self.nodes[0]
        wallet_node = self.nodes[1]

        self.log.info("Set up an active MWEB chain and five distinct wallet outputs")
        self.setup_mweb_chain(funding_node, pegin_amount=Decimal('25'))
        self.sync_all()
        coins = self.create_mweb_coins(
            funding_node,
            wallet_node,
            [Decimal('1'), Decimal('2'), Decimal('3'), Decimal('4'), Decimal('5')],
        )

        self.test_listunspent(wallet_node, coins)
        self.test_locking(funding_node, wallet_node, coins)
        self.test_explicit_inputs(funding_node, wallet_node, coins)
        self.test_invalid_inputs(funding_node, wallet_node, coins)
        self.test_mixed_inputs(funding_node, wallet_node, coins)
        self.test_createpsbt(funding_node, wallet_node, coins[:3])
        self.test_spent_input(funding_node, wallet_node, coins[-1])

    def create_mweb_coins(self, funding_node, wallet_node, amounts):
        payments = []
        for amount in amounts:
            address = wallet_node.getnewaddress(address_type='mweb')
            txid = funding_node.sendtoaddress(address, amount)
            payments.append((address, txid, amount))
            self.sync_mempools()

        self.generate(funding_node, 1, sync_fun=self.sync_all)

        coins = []
        for address, txid, amount in payments:
            utxos = wallet_node.listunspent(addresses=[address])
            assert_equal(len(utxos), 1)
            utxo = utxos[0]
            assert_equal(utxo['txid'], txid)
            assert_equal(utxo['amount'], amount)
            assert 'mweb_out' in utxo
            assert 'vout' not in utxo
            coins.append({
                'address': address,
                'amount': amount,
                'input': {'mweb_out': utxo['mweb_out']},
            })
        return coins

    def test_listunspent(self, wallet, coins):
        self.log.info("listunspent exposes stable MWEB coin-control identifiers and applies amount filters")
        expected_ids = {coin['input']['mweb_out'] for coin in coins[2:4]}
        filtered = wallet.listunspent(
            minconf=1,
            maxconf=9999999,
            addresses=[],
            include_unsafe=True,
            query_options={
                'minimumAmount': Decimal('3'),
                'maximumAmount': Decimal('4'),
            },
        )
        assert_equal({utxo['mweb_out'] for utxo in filtered}, expected_ids)
        assert all('vout' not in utxo for utxo in filtered)

    def test_locking(self, funding_node, wallet, coins):
        self.log.info("lockunspent accepts MWEB ids and automatic selection skips locked MWEB outputs")
        coin = coins[3]
        assert_raises_rpc_error(
            -8,
            "Invalid parameter, expected locked output",
            wallet.lockunspent,
            True,
            [coin['input']],
        )
        wallet.lockunspent(False, [coin['input']])
        assert_equal(wallet.listlockunspent(), [coin['input']])
        assert_equal(wallet.listunspent(addresses=[coin['address']]), [])

        automatic = wallet.walletcreatefundedpsbt(
            [],
            {funding_node.getnewaddress(address_type='mweb'): Decimal('0.5')},
            0,
            {'fee_rate': 10},
        )
        assert coin['input']['mweb_out'] not in self.mweb_input_ids(wallet, automatic['psbt'])

        automatic_sweep = wallet.sendall(
            recipients=[funding_node.getnewaddress(address_type='mweb')],
            options={'add_to_wallet': False, 'fee_rate': 10, 'psbt': True},
        )
        assert automatic_sweep['complete']
        assert coin['input']['mweb_out'] not in self.mweb_input_ids(wallet, automatic_sweep['psbt'])

        self.log.info("A manually selected MWEB coin remains usable while locked")
        manual = wallet.walletcreatefundedpsbt(
            [coin['input']],
            {funding_node.getnewaddress(address_type='mweb'): Decimal('0.5')},
            0,
            {'add_inputs': False, 'fee_rate': 10},
        )
        assert_equal(self.mweb_input_ids(wallet, manual['psbt']), {coin['input']['mweb_out']})

        self.log.info("Non-persistent MWEB locks are cleared on restart")
        self.restart_node(1)
        assert_equal(wallet.listlockunspent(), [])

        self.log.info("Persistent MWEB locks survive restart and unlocking erases the database record")
        wallet.lockunspent(False, [coin['input']])
        wallet.lockunspent(False, [coin['input']], True)
        self.restart_node(1)
        assert_equal(wallet.listlockunspent(), [coin['input']])
        wallet.lockunspent(True, [coin['input']])
        self.restart_node(1)
        assert_equal(wallet.listlockunspent(), [])
        self.connect_nodes(0, 1)

    def test_explicit_inputs(self, funding_node, wallet, coins):
        self.log.info("walletcreatefundedpsbt uses exactly one requested MWEB input and locks it")
        selected = coins[0]
        funded = wallet.walletcreatefundedpsbt(
            [selected['input']],
            {funding_node.getnewaddress(address_type='mweb'): Decimal('0.25')},
            0,
            {
                'add_inputs': False,
                'fee_rate': 10,
                'lockUnspents': True,
            },
        )
        assert_equal(funded['changepos'], 1)
        assert funded['fee'] > 0
        assert_equal(self.mweb_input_ids(wallet, funded['psbt']), {selected['input']['mweb_out']})
        assert_equal(wallet.listlockunspent(), [selected['input']])
        wallet.lockunspent(True, [selected['input']])

        self.log.info("send accepts an exact MWEB input and returns a complete PSBT")
        selected = coins[1]
        sent = wallet.send(
            outputs={funding_node.getnewaddress(address_type='mweb'): Decimal('0.5')},
            options={
                'add_inputs': False,
                'add_to_wallet': False,
                'fee_rate': 10,
                'inputs': [selected['input']],
                'lock_unspents': True,
                'psbt': True,
            },
        )
        assert sent['complete']
        assert 'hex' in sent
        assert 'txid' in sent
        assert_equal(self.mweb_input_ids(wallet, sent['psbt']), {selected['input']['mweb_out']})
        assert_equal(wallet.listlockunspent(), [selected['input']])
        wallet.lockunspent(True, [selected['input']])

        self.log.info("add_inputs controls whether an explicitly selected MWEB coin may be supplemented")
        assert_raises_rpc_error(
            -4,
            "Insufficient funds",
            wallet.walletcreatefundedpsbt,
            [coins[0]['input']],
            {funding_node.getnewaddress(address_type='mweb'): Decimal('1.5')},
            0,
            {'add_inputs': False, 'fee_rate': 10},
        )
        supplemented = wallet.walletcreatefundedpsbt(
            [coins[0]['input']],
            {funding_node.getnewaddress(address_type='mweb'): Decimal('1.5')},
            0,
            {'add_inputs': True, 'fee_rate': 10},
        )
        supplemented_ids = self.mweb_input_ids(wallet, supplemented['psbt'])
        assert coins[0]['input']['mweb_out'] in supplemented_ids
        assert len(supplemented_ids) > 1

        self.log.info("sendall honors an explicit MWEB subset for both MWEB sends and pegouts")
        swept = wallet.sendall(
            recipients=[funding_node.getnewaddress(address_type='mweb')],
            options={
                'add_to_wallet': False,
                'fee_rate': 10,
                'inputs': [coins[0]['input'], coins[1]['input']],
                'lock_unspents': True,
                'psbt': True,
            },
        )
        assert swept['complete']
        assert 'hex' in swept
        assert 'txid' in swept
        swept_decoded = wallet.decodepsbt(swept['psbt'])
        assert 'mweb_tx_offset' in swept_decoded
        assert 'mweb_stealth_offset' in swept_decoded
        assert wallet.finalizepsbt(swept['psbt'])['complete']
        assert_equal(
            self.mweb_input_ids(wallet, swept['psbt']),
            {coins[0]['input']['mweb_out'], coins[1]['input']['mweb_out']},
        )
        assert_equal(self.locked_ids(wallet), {
            ('mweb', coins[0]['input']['mweb_out']),
            ('mweb', coins[1]['input']['mweb_out']),
        })
        wallet.lockunspent(True)

        pegout = wallet.sendall(
            recipients=[funding_node.getnewaddress()],
            options={
                'add_to_wallet': False,
                'fee_rate': 10,
                'inputs': [coins[2]['input']],
                'psbt': True,
            },
        )
        assert pegout['complete']
        decoded = wallet.decodepsbt(pegout['psbt'])
        assert_equal(self.mweb_input_ids(wallet, pegout['psbt']), {coins[2]['input']['mweb_out']})
        assert_equal(len(decoded['kernels'][0]['pegouts']), 1)

        self.log.info("fundrawtransaction reports the PSBT requirement when only MWEB funding is available")
        raw = wallet.createrawtransaction([], {funding_node.getnewaddress(): Decimal('0.25')})
        assert_raises_rpc_error(
            -8,
            "fundrawtransaction cannot return MWEB transaction hex; use walletcreatefundedpsbt for MWEB funding",
            wallet.fundrawtransaction,
            raw,
        )

    def test_invalid_inputs(self, funding_node, wallet, coins):
        self.log.info("MWEB input objects reject malformed, ambiguous, and inapplicable fields")
        recipient = funding_node.getnewaddress(address_type='mweb')
        invalid_id = '00'
        non_hex_id = 'zz' * 32
        unknown_id = '00' * 32

        for output_id in [invalid_id, non_hex_id]:
            assert_raises_rpc_error(
                -8,
                "mweb_out must be a 64-character hexadecimal string",
                wallet.walletcreatefundedpsbt,
                [{'mweb_out': output_id}],
                {recipient: Decimal('0.25')},
            )

        mixed_form = {
            'mweb_out': coins[0]['input']['mweb_out'],
            'txid': coins[0]['input']['mweb_out'],
            'vout': 0,
        }
        assert_raises_rpc_error(
            -8,
            "specify either mweb_out or txid and vout",
            wallet.walletcreatefundedpsbt,
            [mixed_form],
            {recipient: Decimal('0.25')},
        )
        assert_raises_rpc_error(
            -8,
            "specify either mweb_out or txid and vout",
            wallet.lockunspent,
            False,
            [mixed_form],
        )
        for field in ['sequence', 'weight']:
            invalid = dict(coins[0]['input'])
            invalid[field] = 1
            assert_raises_rpc_error(
                -8,
                "sequence and weight do not apply to MWEB inputs",
                wallet.walletcreatefundedpsbt,
                [invalid],
                {recipient: Decimal('0.25')},
            )

        assert_raises_rpc_error(
            -8,
            "MWEB PSBTs require PSBT version 2",
            wallet.walletcreatefundedpsbt,
            [coins[0]['input']],
            {recipient: Decimal('0.25')},
            0,
            {'add_inputs': False, 'fee_rate': 10},
            True,
            0,
        )

        assert_raises_rpc_error(
            -8,
            "unknown MWEB output",
            wallet.lockunspent,
            False,
            [{'mweb_out': unknown_id}],
        )
        assert_raises_rpc_error(
            -4,
            "Unable to find UTXO for external input",
            wallet.walletcreatefundedpsbt,
            [{'mweb_out': unknown_id}],
            {recipient: Decimal('0.25')},
            0,
            {'add_inputs': False, 'fee_rate': 10},
        )
        assert_raises_rpc_error(
            -8,
            "not part of wallet",
            wallet.sendall,
            [recipient],
            None,
            'unset',
            None,
            {'inputs': [{'mweb_out': unknown_id}]},
        )

        self.log.info("lockunspent validates the full request before changing any locks")
        assert_raises_rpc_error(
            -8,
            "unknown MWEB output",
            wallet.lockunspent,
            False,
            [coins[0]['input'], {'mweb_out': unknown_id}],
        )
        assert_equal(wallet.listlockunspent(), [])

    def test_mixed_inputs(self, funding_node, wallet, coins):
        self.log.info("walletcreatefundedpsbt combines explicitly selected transparent and MWEB inputs")
        address = wallet.getnewaddress(address_type='bech32')
        txid = funding_node.sendtoaddress(address, Decimal('1.5'))
        self.sync_mempools()
        self.generate(funding_node, 1, sync_fun=self.sync_all)
        utxos = wallet.listunspent(addresses=[address])
        assert_equal(len(utxos), 1)
        transparent = {'txid': txid, 'vout': utxos[0]['vout']}

        funded = wallet.walletcreatefundedpsbt(
            [transparent, coins[3]['input']],
            {funding_node.getnewaddress(address_type='mweb'): Decimal('2')},
            0,
            {'add_inputs': False, 'fee_rate': 10},
        )
        decoded = wallet.decodepsbt(funded['psbt'])
        assert_equal(len(decoded['inputs']), 2)
        assert_equal(self.mweb_input_ids(wallet, funded['psbt']), {coins[3]['input']['mweb_out']})
        transparent_inputs = [txin for txin in decoded['inputs'] if 'mweb' not in txin]
        assert_equal(len(transparent_inputs), 1)
        assert_equal(transparent_inputs[0]['previous_txid'], transparent['txid'])
        assert_equal(transparent_inputs[0]['previous_vout'], transparent['vout'])

        self.log.info("lockunspent handles mixed transparent/MWEB arrays and unlock-all")
        wallet.lockunspent(False, [transparent, coins[3]['input']])
        assert_equal(self.locked_ids(wallet), {
            ('ltc', transparent['txid'], transparent['vout']),
            ('mweb', coins[3]['input']['mweb_out']),
        })
        wallet.lockunspent(True)
        assert_equal(wallet.listlockunspent(), [])

    def test_spent_input(self, funding_node, wallet, coin):
        self.log.info("Committing a manually selected locked MWEB coin unlocks and spends it")
        wallet.lockunspent(False, [coin['input']])
        assert_equal(wallet.listlockunspent(), [coin['input']])
        sent = wallet.send(
            outputs={funding_node.getnewaddress(address_type='mweb'): Decimal('0.5')},
            options={
                'add_inputs': False,
                'fee_rate': 10,
                'inputs': [coin['input']],
            },
        )
        assert sent['complete']
        self.sync_mempools()
        assert_equal(wallet.listlockunspent(), [])
        assert_equal(wallet.listunspent(addresses=[coin['address']]), [])

        self.log.info("Spent MWEB identifiers are rejected by locking and explicit sendall selection")
        assert_raises_rpc_error(
            -8,
            "expected unspent output",
            wallet.lockunspent,
            False,
            [coin['input']],
        )
        assert_raises_rpc_error(
            -8,
            "was already spent",
            wallet.sendall,
            [funding_node.getnewaddress(address_type='mweb')],
            None,
            'unset',
            None,
            {'inputs': [coin['input']]},
        )

    def test_createpsbt(self, funding_node, wallet, coins):
        self.log.info("createpsbt creates an ID-only MWEB input for the updater role")
        recipient = funding_node.getnewaddress(address_type='mweb')
        fee = Decimal('0.0001')
        selected = coins[:2]
        amount = sum((coin['amount'] for coin in selected), Decimal('0')) - fee
        created = wallet.createpsbt([coin['input'] for coin in selected], {recipient: amount})
        decoded = wallet.decodepsbt(created)
        assert_equal(
            [txin['mweb']['output_id'] for txin in decoded['inputs']],
            [coin['input']['mweb_out'] for coin in selected],
        )
        assert all(set(txin['mweb']) == {'output_id'} for txin in decoded['inputs'])
        assert_equal(wallet.analyzepsbt(created)['next'], 'updater')

        self.log.info("utxoupdatepsbt attaches public fields but leaves the confidential amount to the owner")
        public_updated = funding_node.utxoupdatepsbt(created)
        public_inputs = [txin['mweb'] for txin in funding_node.decodepsbt(public_updated)['inputs']]
        assert all('output_commit' in txin for txin in public_inputs)
        assert all('output_pubkey' in txin for txin in public_inputs)
        assert all('amount' not in txin for txin in public_inputs)
        assert_equal(funding_node.analyzepsbt(public_updated)['next'], 'updater')

        self.log.info("walletprocesspsbt supplies private metadata and infers the MWEB kernel fee")
        private_updated = wallet.walletprocesspsbt(public_updated, False)
        assert not private_updated['complete']
        updated_decoded = wallet.decodepsbt(private_updated['psbt'])
        updated_inputs = [txin['mweb'] for txin in updated_decoded['inputs']]
        assert_equal(
            [txin['amount'] for txin in updated_inputs],
            [self.to_litoshis(coin['amount']) for coin in selected],
        )
        assert all('shared_secret' in txin for txin in updated_inputs)
        assert all(txin['address_descriptor'].startswith('mweb(') for txin in updated_inputs)
        assert all('signature' not in txin for txin in updated_inputs)
        assert_equal(len(updated_decoded['kernels']), 1)
        assert_equal(updated_decoded['kernels'][0]['fee'], self.to_litoshis(fee))
        analysis = wallet.analyzepsbt(private_updated['psbt'])
        assert_equal(analysis['next'], 'signer')
        assert_equal(analysis['fee'], fee)

        signed = wallet.walletprocesspsbt(private_updated['psbt'])
        assert signed['complete']
        for combined in [
            wallet.combinepsbt([created, signed['psbt']]),
            wallet.combinepsbt([signed['psbt'], created]),
        ]:
            assert wallet.finalizepsbt(combined)['complete']
        finalized = wallet.finalizepsbt(signed['psbt'])
        assert finalized['complete']
        funding_node.sendrawtransaction(finalized['hex'], 0)

        self.log.info("Transparent createpsbt destinations become pegouts for MWEB-only inputs")
        pegout_recipient = funding_node.getnewaddress(address_type='bech32')
        pegout_amount = coins[2]['amount'] - fee
        pegout_created = wallet.createpsbt([coins[2]['input']], {pegout_recipient: pegout_amount})
        pegout_decoded = wallet.decodepsbt(pegout_created)
        assert_equal(len(pegout_decoded['outputs']), 0)
        assert_equal(len(pegout_decoded['kernels']), 1)
        assert 'fee' not in pegout_decoded['kernels'][0]
        assert_equal(len(pegout_decoded['kernels'][0]['pegouts']), 1)
        assert_equal(pegout_decoded['kernels'][0]['pegouts'][0]['amount'], self.to_litoshis(pegout_amount))
        assert_equal(pegout_decoded['kernels'][0]['pegouts'][0]['scriptPubKey']['address'], pegout_recipient)

        pegout_signed = wallet.walletprocesspsbt(pegout_created)
        assert pegout_signed['complete']
        assert wallet.finalizepsbt(wallet.combinepsbt([pegout_created, pegout_signed['psbt']]))['complete']
        pegout_finalized = wallet.finalizepsbt(pegout_signed['psbt'])
        assert pegout_finalized['complete']
        funding_node.sendrawtransaction(pegout_finalized['hex'], 0)
        self.sync_mempools()
        self.generate(funding_node, 1, sync_fun=self.sync_all)

        received = funding_node.listunspent(addresses=[recipient])
        assert_equal(len(received), 1)
        assert_equal(received[0]['amount'], amount)
        pegout_received = funding_node.listreceivedbyaddress(minconf=1, address_filter=pegout_recipient)
        assert_equal(len(pegout_received), 1)
        assert_equal(pegout_received[0]['amount'], pegout_amount)

        self.log.info("createpsbt validates MWEB identifiers and rejects ambiguous input layers")
        unknown = {'mweb_out': '11' * 32}
        unknown_psbt = wallet.createpsbt([unknown], {wallet.getnewaddress(address_type='mweb'): Decimal('0.1')})
        assert_equal(wallet.analyzepsbt(unknown_psbt)['next'], 'updater')
        assert not wallet.walletprocesspsbt(unknown_psbt)['complete']

        for output_id in ['00', 'zz' * 32]:
            assert_raises_rpc_error(
                -8,
                "mweb_out must be a 64-character hexadecimal string",
                wallet.createpsbt,
                [{'mweb_out': output_id}],
                {wallet.getnewaddress(address_type='mweb'): Decimal('0.1')},
            )

        mixed_form = {'mweb_out': unknown['mweb_out'], 'txid': unknown['mweb_out'], 'vout': 0}
        assert_raises_rpc_error(
            -8,
            "specify either mweb_out or txid and vout",
            wallet.createpsbt,
            [mixed_form],
            {wallet.getnewaddress(address_type='mweb'): Decimal('0.1')},
        )
        assert_raises_rpc_error(
            -8,
            "sequence and weight do not apply to MWEB inputs",
            wallet.createpsbt,
            [dict(unknown, sequence=1)],
            {wallet.getnewaddress(address_type='mweb'): Decimal('0.1')},
        )
        assert_raises_rpc_error(
            -8,
            "MWEB PSBTs require PSBT version 2",
            wallet.createpsbt,
            [unknown],
            {wallet.getnewaddress(address_type='mweb'): Decimal('0.1')},
            0,
            False,
            0,
        )
        assert_raises_rpc_error(
            -8,
            "MWEB inputs cannot be represented in raw transaction hex",
            wallet.createrawtransaction,
            [unknown],
            {wallet.getnewaddress(): Decimal('0.1')},
        )

        transparent = next(utxo for utxo in wallet.listunspent() if 'vout' in utxo)
        assert_raises_rpc_error(
            -8,
            "Mixed transparent and MWEB inputs require explicit peg-in or pegout metadata",
            wallet.createpsbt,
            [unknown, {'txid': transparent['txid'], 'vout': transparent['vout']}],
            {wallet.getnewaddress(address_type='mweb'): Decimal('0.1')},
        )

    def mweb_input_ids(self, wallet, psbt):
        return {
            txin['mweb']['output_id']
            for txin in wallet.decodepsbt(psbt)['inputs']
            if 'mweb' in txin
        }

    def to_litoshis(self, amount):
        return int(amount * Decimal('100000000'))

    def locked_ids(self, wallet):
        result = set()
        for output in wallet.listlockunspent():
            if 'mweb_out' in output:
                result.add(('mweb', output['mweb_out']))
            else:
                result.add(('ltc', output['txid'], output['vout']))
        return result


if __name__ == '__main__':
    MWEBWalletCoinControlTest().main()
