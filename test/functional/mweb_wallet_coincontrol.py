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

    def mweb_input_ids(self, wallet, psbt):
        return {
            txin['mweb']['output_id']
            for txin in wallet.decodepsbt(psbt)['inputs']
            if 'mweb' in txin
        }

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
