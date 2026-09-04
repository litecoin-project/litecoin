#!/usr/bin/env python3
# Copyright (c) 2026 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test public wallet policy for MWEB recipients and change."""

from decimal import Decimal

from test_framework.test_framework import LitecoinTestFramework
from test_framework.util import assert_equal


class MWEBWalletRecipientPolicyTest(LitecoinTestFramework):
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
        sender = self.nodes[0]
        receiver = self.nodes[1]

        self.log.info("Set up spendable balances on both the LTC and MWEB layers")
        self.setup_mweb_chain(sender, pegin_amount=Decimal('30'))
        self.sync_all()

        ltc_coins = [coin for coin in sender.listunspent() if 'vout' in coin]
        assert len(ltc_coins) >= 2

        self.test_mixed_fee_subtraction(sender, receiver, ltc_coins[0])
        custom_change = self.test_custom_mweb_change(sender, receiver, ltc_coins[1])
        self.test_mixed_send_from_mweb(sender, receiver, custom_change)
        self.test_sendmany_mweb_recipients(sender, receiver)
        self.test_sendall_mixed_recipients(sender, receiver)

    def test_mixed_fee_subtraction(self, sender, receiver, coin):
        self.log.info("walletcreatefundedpsbt splits fees across LTC and MWEB recipients")
        ltc_recipient = receiver.getnewaddress(address_type='bech32')
        mweb_recipient = receiver.getnewaddress(address_type='mweb')
        ltc_requested = coin['amount'] / 2
        mweb_requested = coin['amount'] - ltc_requested

        funded = sender.walletcreatefundedpsbt(
            [{'txid': coin['txid'], 'vout': coin['vout']}],
            [{ltc_recipient: ltc_requested}, {mweb_recipient: mweb_requested}],
            0,
            {
                'add_inputs': False,
                'fee_rate': 10,
                'subtractFeeFromOutputs': [0, 1],
            },
        )
        assert_equal(funded['changepos'], -1)
        assert funded['fee'] > 0

        decoded = sender.decodepsbt(funded['psbt'])
        ltc_output = self.output_for_address(decoded, ltc_recipient)
        mweb_output = self.output_for_address(decoded, mweb_recipient)
        assert ltc_output['amount'] < ltc_requested
        assert mweb_output['amount'] < mweb_requested
        assert_equal(
            ltc_output['amount'] + mweb_output['amount'],
            coin['amount'] - funded['fee'],
        )
        assert_equal(sender.analyzepsbt(funded['psbt'])['next'], 'signer')

    def test_custom_mweb_change(self, sender, receiver, coin):
        self.log.info("walletcreatefundedpsbt applies and reports custom MWEB change")
        ltc_recipient = receiver.getnewaddress(address_type='bech32')
        mweb_recipient = receiver.getnewaddress(address_type='mweb')
        change_address = sender.getnewaddress(address_type='mweb')

        funded = sender.walletcreatefundedpsbt(
            [{'txid': coin['txid'], 'vout': coin['vout']}],
            [{ltc_recipient: Decimal('1')}, {mweb_recipient: Decimal('2')}],
            0,
            {
                'add_inputs': False,
                'changeAddress': change_address,
                'changePosition': 0,
                'fee_rate': 10,
            },
        )
        decoded = sender.decodepsbt(funded['psbt'])
        change_position = funded['changepos']
        assert change_position != 0
        assert_equal(decoded['outputs'][change_position]['mweb']['address'], change_address)

        change_amount = coin['amount'] - Decimal('3') - funded['fee']
        assert_equal(decoded['outputs'][change_position]['amount'], change_amount)
        assert_equal(self.output_for_address(decoded, ltc_recipient)['amount'], Decimal('1'))
        assert_equal(self.output_for_address(decoded, mweb_recipient)['amount'], Decimal('2'))
        assert all('mweb' not in txin for txin in decoded['inputs'])
        assert_equal(len(decoded['kernels']), 1)
        assert 'pegin_amount' in decoded['kernels'][0]
        assert 'pegouts' not in decoded['kernels'][0]

        txid = self.broadcast_psbt(sender, funded['psbt'])
        self.generate(sender, 1, sync_fun=self.sync_all)
        assert_equal(sender.gettransaction(txid)['confirmations'], 1)
        assert_equal(receiver.listunspent(addresses=[ltc_recipient])[0]['amount'], Decimal('1'))
        assert_equal(receiver.listunspent(addresses=[mweb_recipient])[0]['amount'], Decimal('2'))

        change = sender.listunspent(addresses=[change_address])
        assert_equal(len(change), 1)
        assert_equal(change[0]['amount'], change_amount)
        assert 'mweb_out' in change[0]
        return change[0]

    def test_mixed_send_from_mweb(self, sender, receiver, change):
        self.log.info("send pays mixed recipients from one selected MWEB input")
        ltc_recipient = receiver.getnewaddress(address_type='bech32')
        mweb_recipient = receiver.getnewaddress(address_type='mweb')
        sent = sender.send(
            outputs=[{ltc_recipient: Decimal('0.4')}, {mweb_recipient: Decimal('0.6')}],
            options={
                'add_inputs': False,
                'add_to_wallet': False,
                'fee_rate': 10,
                'inputs': [{'mweb_out': change['mweb_out']}],
                'psbt': True,
            },
        )
        assert sent['complete']
        decoded = sender.decodepsbt(sent['psbt'])
        assert_equal(
            [txin['mweb']['output_id'] for txin in decoded['inputs']],
            [change['mweb_out']],
        )
        assert_equal(self.output_for_address(decoded, mweb_recipient)['amount'], Decimal('0.6'))
        assert_equal(len(decoded['kernels']), 1)
        assert 'pegin_amount' not in decoded['kernels'][0]
        assert_equal(len(decoded['kernels'][0]['pegouts']), 1)
        assert_equal(decoded['kernels'][0]['pegouts'][0]['amount'], self.to_litoshis(Decimal('0.4')))
        assert_equal(decoded['kernels'][0]['pegouts'][0]['scriptPubKey']['address'], ltc_recipient)

        receiver_balance = self.wallet_total(receiver)
        assert_equal(sender.sendrawtransaction(sent['hex'], 0), sent['txid'])
        # The following block's HogEx materializes an external pegout.
        self.generate(sender, 2, sync_fun=self.sync_all)
        assert_equal(receiver.listunspent(addresses=[mweb_recipient])[0]['amount'], Decimal('0.6'))
        assert_equal(self.wallet_total(receiver) - receiver_balance, Decimal('1'))

    def test_sendmany_mweb_recipients(self, sender, receiver):
        self.log.info("sendmany pays several MWEB recipients in one transaction")
        recipient1 = receiver.getnewaddress(address_type='mweb')
        recipient2 = receiver.getnewaddress(address_type='mweb')
        txid = sender.sendmany(
            '',
            {
                recipient1: Decimal('0.3'),
                recipient2: Decimal('0.7'),
            },
        )
        self.sync_mempools()
        self.generate(sender, 1, sync_fun=self.sync_all)

        assert_equal(sender.gettransaction(txid)['confirmations'], 1)
        assert_equal(receiver.listunspent(addresses=[recipient1])[0]['amount'], Decimal('0.3'))
        assert_equal(receiver.listunspent(addresses=[recipient2])[0]['amount'], Decimal('0.7'))

    def test_sendall_mixed_recipients(self, sender, receiver):
        self.log.info("sendall sweeps combined LTC and MWEB inputs to mixed recipients")
        ltc_recipient = receiver.getnewaddress(address_type='bech32')
        mweb_recipient = receiver.getnewaddress(address_type='mweb')
        swept = sender.sendall(
            recipients=[ltc_recipient, {mweb_recipient: Decimal('0.25')}],
            options={
                'add_to_wallet': False,
                'fee_rate': 10,
                'psbt': True,
            },
        )
        assert swept['complete']
        decoded = sender.decodepsbt(swept['psbt'])
        assert any('mweb' in txin for txin in decoded['inputs'])
        assert any('mweb' not in txin for txin in decoded['inputs'])
        assert_equal(self.output_for_address(decoded, mweb_recipient)['amount'], Decimal('0.25'))
        assert_equal(len(decoded['kernels']), 1)
        assert 'pegin_amount' in decoded['kernels'][0]
        assert_equal(len(decoded['kernels'][0]['pegouts']), 1)
        assert_equal(decoded['kernels'][0]['pegouts'][0]['scriptPubKey']['address'], ltc_recipient)

        pegout_amount = Decimal(decoded['kernels'][0]['pegouts'][0]['amount']) / Decimal('100000000')
        receiver_balance = self.wallet_total(receiver)
        assert_equal(sender.sendrawtransaction(swept['hex'], 0), swept['txid'])
        # The following block's HogEx materializes an external pegout.
        self.generate(sender, 2, sync_fun=self.sync_all)
        assert_equal(receiver.listunspent(addresses=[mweb_recipient])[0]['amount'], Decimal('0.25'))
        assert_equal(self.wallet_total(receiver) - receiver_balance, Decimal('0.25') + pegout_amount)

    def broadcast_psbt(self, wallet, psbt):
        processed = wallet.walletprocesspsbt(psbt)
        assert processed['complete']
        finalized = wallet.finalizepsbt(processed['psbt'])
        assert finalized['complete']
        txid = wallet.sendrawtransaction(finalized['hex'], 0)
        self.sync_mempools()
        return txid

    def output_for_address(self, decoded, address):
        matching = [
            output
            for output in decoded['outputs']
            if output.get('mweb', {}).get('address') == address
            or output.get('script', {}).get('address') == address
        ]
        assert_equal(len(matching), 1)
        return matching[0]

    def to_litoshis(self, amount):
        return int(amount * Decimal('100000000'))

    def wallet_total(self, wallet):
        balances = wallet.getbalances()['mine']
        return balances['trusted'] + balances['immature']


if __name__ == '__main__':
    MWEBWalletRecipientPolicyTest().main()
