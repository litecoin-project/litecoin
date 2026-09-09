#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the rawtransaction RPCs.

Test the following RPCs:
    - createrawtransaction
    - signrawtransactionwithwallet
    - sendrawtransaction
    - decoderawtransaction
    - getrawtransaction
    - combinerawtransaction
    - testmempoolaccept

Refactored from the upstream Bitcoin Core test of the same name:
    - run_test() split into one method per RPC/feature area instead of a
      single 500-line function, so failures point at a named scenario.
    - The two near-identical "small fee" / "large fee" testmempoolaccept
      blocks are now one parameterized helper.
    - Naming normalized to snake_case throughout (was a mix of camelCase
      and snake_case).
    - The placeholder-but-oddly-shaped 65-char txid used for RPC
      parameter-validation tests (never resolved on chain) now lives in
      one named constant instead of being retyped at each call site.
"""

from collections import OrderedDict
from decimal import Decimal
from io import BytesIO

from test_framework.messages import CTransaction, ToHex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    find_vout_for_address,
    hex_str_to_bytes,
)

# Used only to exercise input-validation error paths (missing vout,
# missing prevout info, etc). It is intentionally never a real, spendable
# on-chain txid, and every call site that uses it expects an RPC error
# rather than a resolved transaction.
PLACEHOLDER_TXID = '1d1d4e24ed99057e84c3f80fd8fbec79ed9e1acee37da269356ecea000000000'


class MultiDict(dict):
    """Dictionary that allows duplicate keys.

    Constructed with a list of (key, value) tuples. When dumped by the json
    module, will output invalid json with repeated keys, e.g.:

        >>> json.dumps(MultiDict([(1, 2), (1, 2)]))
        '{"1": 2, "1": 2}'

    Used to test RPC calls with repeated keys in the JSON object -- a shape
    Python's own dict can't represent, since real dicts collapse duplicate
    keys before we ever get to serialize them.
    """

    def __init__(self, items):
        dict.__init__(self, items)
        self._items = items

    def items(self):
        return self._items


class RawTransactionsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [
            ["-txindex"],
            ["-txindex"],
            ["-txindex"],
        ]
        self.supports_cli = False

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        super().setup_network()
        self.connect_nodes(0, 2)

    def run_test(self):
        self.log.info('prepare some coins for multiple *rawtransaction commands')
        self.fund_nodes()

        self.test_genesis_coinbase_error()
        self.test_createrawtransaction_input_validation()
        self.test_createrawtransaction_output_validation()
        self.test_createrawtransaction_locktime_and_replaceable_validation()
        self.test_createrawtransaction_outputs_shape()
        self.test_signrawtransactionwithwallet_prevtxs()
        self.test_sendrawtransaction_missing_input()
        self.test_getrawtransaction_with_blockhash()

        if not self.options.descriptors:
            # The traditional multisig workflow does not work with
            # descriptor wallets, so this section is legacy-wallet only.
            # The descriptor-wallet multisig workflow uses PSBTs and is
            # tested elsewhere.
            self.test_multisig_2of2()
            self.test_multisig_2of3_across_nodes()
            self.test_multisig_2of2_combine()

        self.test_decoderawtransaction()
        self.test_basic_signrawtransaction_and_getrawtransaction()
        self.test_sequence_number_validation()
        self.test_transaction_version_number_bounds()
        self.test_sendrawtransaction_maxfeerate()

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def fund_nodes(self):
        self.nodes[2].generate(1)
        self.sync_all()
        self.nodes[0].generate(101)
        self.sync_all()

        self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 1.5)
        self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 1.0)
        self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 5.0)
        self.sync_all()

        self.nodes[0].generate(5)
        self.sync_all()

    # ------------------------------------------------------------------
    # getrawtransaction / genesis coinbase
    # ------------------------------------------------------------------

    def test_genesis_coinbase_error(self):
        self.log.info('Test getrawtransaction on genesis block coinbase returns an error')
        block = self.nodes[0].getblock(self.nodes[0].getblockhash(0))
        assert_raises_rpc_error(
            -5, "The genesis block coinbase is not considered an ordinary transaction",
            self.nodes[0].getrawtransaction, block['merkleroot'],
        )

    # ------------------------------------------------------------------
    # createrawtransaction validation
    # ------------------------------------------------------------------

    def test_createrawtransaction_input_validation(self):
        self.log.info('Check parameter types and required parameters of createrawtransaction')
        node = self.nodes[0]

        # Required parameters
        assert_raises_rpc_error(-1, "createrawtransaction", node.createrawtransaction)
        assert_raises_rpc_error(-1, "createrawtransaction", node.createrawtransaction, [])

        # Invalid extra parameters
        assert_raises_rpc_error(-1, "createrawtransaction", node.createrawtransaction, [], {}, 0, False, 'foo')

        # Invalid `inputs`
        txid = PLACEHOLDER_TXID
        assert_raises_rpc_error(-3, "Expected type array", node.createrawtransaction, 'foo', {})
        assert_raises_rpc_error(-1, "JSON value is not an object as expected", node.createrawtransaction, ['foo'], {})
        assert_raises_rpc_error(-1, "JSON value is not a string as expected", node.createrawtransaction, [{}], {})
        assert_raises_rpc_error(
            -8, "txid must be of length 64 (not 3, for 'foo')",
            node.createrawtransaction, [{'txid': 'foo'}], {},
        )
        assert_raises_rpc_error(
            -8, "txid must be hexadecimal string (not 'ZZZ7bb8b1697ea987f3b223ba7819250cae33efacb068d23dc24859824a77844')",
            node.createrawtransaction, [{'txid': 'ZZZ7bb8b1697ea987f3b223ba7819250cae33efacb068d23dc24859824a77844'}], {},
        )
        assert_raises_rpc_error(-8, "Invalid parameter, missing vout key", node.createrawtransaction, [{'txid': txid}], {})
        assert_raises_rpc_error(
            -8, "Invalid parameter, missing vout key",
            node.createrawtransaction, [{'txid': txid, 'vout': 'foo'}], {},
        )
        assert_raises_rpc_error(
            -8, "Invalid parameter, vout cannot be negative",
            node.createrawtransaction, [{'txid': txid, 'vout': -1}], {},
        )
        assert_raises_rpc_error(
            -8, "Invalid parameter, sequence number is out of range",
            node.createrawtransaction, [{'txid': txid, 'vout': 0, 'sequence': -1}], {},
        )

    def test_createrawtransaction_output_validation(self):
        node = self.nodes[0]
        address = node.getnewaddress()

        assert_raises_rpc_error(-1, "JSON value is not an array as expected", node.createrawtransaction, [], 'foo')
        node.createrawtransaction(inputs=[], outputs={})  # Should not throw, for backwards compatibility
        node.createrawtransaction(inputs=[], outputs=[])

        assert_raises_rpc_error(-8, "Data must be hexadecimal string", node.createrawtransaction, [], {'data': 'foo'})
        assert_raises_rpc_error(-5, "Invalid Litecoin address", node.createrawtransaction, [], {'foo': 0})
        assert_raises_rpc_error(-3, "Invalid amount", node.createrawtransaction, [], {address: 'foo'})
        assert_raises_rpc_error(-3, "Amount out of range", node.createrawtransaction, [], {address: -1})
        assert_raises_rpc_error(
            -8, "Invalid parameter, duplicated address: %s" % address,
            node.createrawtransaction, [], MultiDict([(address, 1), (address, 1)]),
        )
        assert_raises_rpc_error(
            -8, "Invalid parameter, duplicated address: %s" % address,
            node.createrawtransaction, [], [{address: 1}, {address: 1}],
        )
        assert_raises_rpc_error(
            -8, "Invalid parameter, duplicate key: data",
            node.createrawtransaction, [], [{"data": 'aa'}, {"data": "bb"}],
        )
        assert_raises_rpc_error(
            -8, "Invalid parameter, duplicate key: data",
            node.createrawtransaction, [], MultiDict([("data", 'aa'), ("data", "bb")]),
        )
        assert_raises_rpc_error(
            -8, "Invalid parameter, key-value pair must contain exactly one key",
            node.createrawtransaction, [], [{'a': 1, 'b': 2}],
        )
        assert_raises_rpc_error(
            -8, "Invalid parameter, key-value pair not an object as expected",
            node.createrawtransaction, [], [['key-value pair1'], ['2']],
        )

    def test_createrawtransaction_locktime_and_replaceable_validation(self):
        node = self.nodes[0]

        assert_raises_rpc_error(-3, "Expected type number", node.createrawtransaction, [], {}, 'foo')
        assert_raises_rpc_error(-8, "Invalid parameter, locktime out of range", node.createrawtransaction, [], {}, -1)
        assert_raises_rpc_error(
            -8, "Invalid parameter, locktime out of range",
            node.createrawtransaction, [], {}, 4294967296,
        )
        assert_raises_rpc_error(-3, "Expected type bool", node.createrawtransaction, [], {}, 0, 'foo')

    def test_createrawtransaction_outputs_shape(self):
        self.log.info('Check that createrawtransaction accepts an array and object as outputs')
        node = self.nodes[2]
        address = self.nodes[0].getnewaddress()
        address2 = self.nodes[0].getnewaddress()
        txid = PLACEHOLDER_TXID
        tx = CTransaction()

        # One output
        tx.deserialize(BytesIO(hex_str_to_bytes(
            node.createrawtransaction(inputs=[{'txid': txid, 'vout': 9}], outputs={address: 99})
        )))
        assert_equal(len(tx.vout), 1)
        assert_equal(
            tx.serialize().hex(),
            node.createrawtransaction(inputs=[{'txid': txid, 'vout': 9}], outputs=[{address: 99}]),
        )

        # Two outputs
        tx.deserialize(BytesIO(hex_str_to_bytes(
            node.createrawtransaction(
                inputs=[{'txid': txid, 'vout': 9}],
                outputs=OrderedDict([(address, 99), (address2, 99)]),
            )
        )))
        assert_equal(len(tx.vout), 2)
        assert_equal(
            tx.serialize().hex(),
            node.createrawtransaction(
                inputs=[{'txid': txid, 'vout': 9}],
                outputs=[{address: 99}, {address2: 99}],
            ),
        )

        # Multiple mixed outputs
        tx.deserialize(BytesIO(hex_str_to_bytes(
            node.createrawtransaction(
                inputs=[{'txid': txid, 'vout': 9}],
                outputs=MultiDict([(address, 99), (address2, 99), ('data', '99')]),
            )
        )))
        assert_equal(len(tx.vout), 3)
        assert_equal(
            tx.serialize().hex(),
            node.createrawtransaction(
                inputs=[{'txid': txid, 'vout': 9}],
                outputs=[{address: 99}, {address2: 99}, {'data': '99'}],
            ),
        )

    # ------------------------------------------------------------------
    # signrawtransactionwithwallet prevtxs
    # ------------------------------------------------------------------

    def test_signrawtransactionwithwallet_prevtxs(self):
        node = self.nodes[0]
        txid = PLACEHOLDER_TXID

        for address_type in ["bech32", "p2sh-segwit", "legacy"]:
            addr = node.getnewaddress("", address_type)
            addr_info = node.getaddressinfo(addr)
            pubkey = addr_info["scriptPubKey"]

            self.log.info('sendrawtransaction with missing prevtx info (%s)' % address_type)

            inputs = [{'txid': txid, 'vout': 3, 'sequence': 1000}]
            outputs = {node.getnewaddress(): 1}
            rawtx = node.createrawtransaction(inputs, outputs)
            prevtx = dict(txid=txid, scriptPubKey=pubkey, vout=3, amount=1)

            signed = node.signrawtransactionwithwallet(rawtx, [prevtx])
            assert signed["complete"]

            if address_type == "legacy":
                del prevtx["amount"]
                signed = node.signrawtransactionwithwallet(rawtx, [prevtx])
                assert signed["complete"]

            if address_type != "legacy":
                assert_raises_rpc_error(
                    -3, "Missing amount", node.signrawtransactionwithwallet, rawtx,
                    [{"txid": txid, "scriptPubKey": pubkey, "vout": 3}],
                )
                assert_raises_rpc_error(
                    -3, "Missing vout", node.signrawtransactionwithwallet, rawtx,
                    [{"txid": txid, "scriptPubKey": pubkey, "amount": 1}],
                )
                assert_raises_rpc_error(
                    -3, "Missing txid", node.signrawtransactionwithwallet, rawtx,
                    [{"scriptPubKey": pubkey, "vout": 3, "amount": 1}],
                )
                assert_raises_rpc_error(
                    -3, "Missing scriptPubKey", node.signrawtransactionwithwallet, rawtx,
                    [{"txid": txid, "vout": 3, "amount": 1}],
                )

    # ------------------------------------------------------------------
    # sendrawtransaction
    # ------------------------------------------------------------------

    def test_sendrawtransaction_missing_input(self):
        self.log.info('sendrawtransaction with missing input')
        inputs = [{'txid': PLACEHOLDER_TXID, 'vout': 1}]  # Doesn't exist
        outputs = {self.nodes[0].getnewaddress(): 4.998}
        rawtx = self.nodes[2].createrawtransaction(inputs, outputs)
        rawtx = self.nodes[2].signrawtransactionwithwallet(rawtx)

        assert_raises_rpc_error(
            -25, "bad-txns-inputs-missingorspent",
            self.nodes[2].sendrawtransaction, rawtx['hex'],
        )

    def test_getrawtransaction_with_blockhash(self):
        # Make a tx by sending, then generate 2 blocks; block1 has the tx in it.
        tx = self.nodes[2].sendtoaddress(self.nodes[1].getnewaddress(), 1)
        block1, block2 = self.nodes[2].generate(2)
        self.sync_all()

        # We should be able to get the raw transaction by providing the correct block.
        gottx = self.nodes[0].getrawtransaction(tx, True, block1)
        assert_equal(gottx['txid'], tx)
        assert_equal(gottx['in_active_chain'], True)

        # We should not have the 'in_active_chain' flag when we don't provide a block.
        gottx = self.nodes[0].getrawtransaction(tx, True)
        assert_equal(gottx['txid'], tx)
        assert 'in_active_chain' not in gottx

        # We should not get the tx if we provide an unrelated block.
        assert_raises_rpc_error(-5, "No such transaction found", self.nodes[0].getrawtransaction, tx, True, block2)

        # An invalid block hash should raise the correct errors.
        assert_raises_rpc_error(
            -1, "JSON value is not a string as expected",
            self.nodes[0].getrawtransaction, tx, True, True,
        )
        assert_raises_rpc_error(
            -8, "parameter 3 must be of length 64 (not 6, for 'foobar')",
            self.nodes[0].getrawtransaction, tx, True, "foobar",
        )
        assert_raises_rpc_error(
            -8, "parameter 3 must be of length 64 (not 8, for 'abcd1234')",
            self.nodes[0].getrawtransaction, tx, True, "abcd1234",
        )
        assert_raises_rpc_error(
            -8, "parameter 3 must be hexadecimal string (not 'ZZZ0000000000000000000000000000000000000000000000000000000000000')",
            self.nodes[0].getrawtransaction, tx, True, "ZZZ0000000000000000000000000000000000000000000000000000000000000",
        )
        assert_raises_rpc_error(
            -5, "Block hash not found",
            self.nodes[0].getrawtransaction, tx, True,
            "0000000000000000000000000000000000000000000000000000000000000000",
        )

        # Undo the blocks and check in_active_chain.
        self.nodes[0].invalidateblock(block1)
        gottx = self.nodes[0].getrawtransaction(txid=tx, verbose=True, blockhash=block1)
        assert_equal(gottx['in_active_chain'], False)
        self.nodes[0].reconsiderblock(block1)
        assert_equal(self.nodes[0].getbestblockhash(), block2)

    # ------------------------------------------------------------------
    # Multisig (legacy wallet only)
    # ------------------------------------------------------------------

    def test_multisig_2of2(self):
        addr1 = self.nodes[2].getnewaddress()
        addr2 = self.nodes[2].getnewaddress()
        addr1_obj = self.nodes[2].getaddressinfo(addr1)
        addr2_obj = self.nodes[2].getaddressinfo(addr2)

        assert_raises_rpc_error(-5, "Invalid public key", self.nodes[0].createmultisig, 1, ["01020304"])
        self.nodes[0].createmultisig(2, [addr1_obj['pubkey'], addr2_obj['pubkey']])  # createmultisig only takes public keys
        # addmultisigaddress can take both pubkeys and addresses, as long as they are in the wallet.
        assert_raises_rpc_error(-5, "Invalid public key", self.nodes[0].createmultisig, 2, [addr1_obj['pubkey'], addr1])

        multisig_addr = self.nodes[2].addmultisigaddress(2, [addr1_obj['pubkey'], addr1])['address']

        # Use balance deltas instead of absolute values.
        bal = self.nodes[2].getbalance()
        self.nodes[0].sendtoaddress(multisig_addr, 1.2)
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_all()
        # node2 has both keys of the 2-of-2 multisig address, so the tx should affect its balance.
        assert_equal(self.nodes[2].getbalance(), bal + Decimal('1.20000000'))

    def test_multisig_2of3_across_nodes(self):
        bal = self.nodes[2].getbalance()
        addr1 = self.nodes[1].getnewaddress()
        addr2 = self.nodes[2].getnewaddress()
        addr3 = self.nodes[2].getnewaddress()
        addr1_obj = self.nodes[1].getaddressinfo(addr1)
        addr2_obj = self.nodes[2].getaddressinfo(addr2)
        addr3_obj = self.nodes[2].getaddressinfo(addr3)

        multisig_addr = self.nodes[2].addmultisigaddress(
            2, [addr1_obj['pubkey'], addr2_obj['pubkey'], addr3_obj['pubkey']],
        )['address']

        txid = self.nodes[0].sendtoaddress(multisig_addr, 2.2)
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_all()

        # Node2 holds two of three keys, but per this test's original assumption the funds
        # of a 2-of-3 multisig tx are not (yet) marked spendable, so balance is unchanged.
        assert_equal(self.nodes[2].getbalance(), bal)

        tx_details = self.nodes[0].gettransaction(txid, True)
        raw_tx = self.nodes[0].decoderawtransaction(tx_details['hex'])
        vout = next(o for o in raw_tx['vout'] if o['value'] == Decimal('2.20000000'))

        bal = self.nodes[0].getbalance()
        inputs = [{
            "txid": txid,
            "vout": vout['n'],
            "scriptPubKey": vout['scriptPubKey']['hex'],
            "amount": vout['value'],
        }]
        outputs = {self.nodes[0].getnewaddress(): 2.19}
        raw_tx = self.nodes[2].createrawtransaction(inputs, outputs)

        partial_signed = self.nodes[1].signrawtransactionwithwallet(raw_tx, inputs)
        assert_equal(partial_signed['complete'], False)  # node1 has only one key

        fully_signed = self.nodes[2].signrawtransactionwithwallet(raw_tx, inputs)
        assert_equal(fully_signed['complete'], True)  # node2 has two of three keys

        self.nodes[2].sendrawtransaction(fully_signed['hex'])
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_all()

        assert_equal(self.nodes[0].getbalance(), bal + Decimal('50.00000000') + Decimal('2.19000000'))

    def test_multisig_2of2_combine(self):
        bal = self.nodes[2].getbalance()
        addr1 = self.nodes[1].getnewaddress()
        addr2 = self.nodes[2].getnewaddress()
        addr1_obj = self.nodes[1].getaddressinfo(addr1)
        addr2_obj = self.nodes[2].getaddressinfo(addr2)

        self.nodes[1].addmultisigaddress(2, [addr1_obj['pubkey'], addr2_obj['pubkey']])['address']
        multisig_addr = self.nodes[2].addmultisigaddress(2, [addr1_obj['pubkey'], addr2_obj['pubkey']])['address']
        multisig_addr_valid = self.nodes[2].getaddressinfo(multisig_addr)

        txid = self.nodes[0].sendtoaddress(multisig_addr, 2.2)
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_all()

        # The funds of a 2-of-2 multisig tx should not be marked as spendable by either single key.
        assert_equal(self.nodes[2].getbalance(), bal)

        tx_details = self.nodes[0].gettransaction(txid, True)
        raw_tx = self.nodes[0].decoderawtransaction(tx_details['hex'])
        vout = next(o for o in raw_tx['vout'] if o['value'] == Decimal('2.20000000'))

        bal = self.nodes[0].getbalance()
        inputs = [{
            "txid": txid,
            "vout": vout['n'],
            "scriptPubKey": vout['scriptPubKey']['hex'],
            "redeemScript": multisig_addr_valid['hex'],
            "amount": vout['value'],
        }]
        outputs = {self.nodes[0].getnewaddress(): 2.19}
        raw_tx = self.nodes[2].createrawtransaction(inputs, outputs)

        partial_signed_1 = self.nodes[1].signrawtransactionwithwallet(raw_tx, inputs)
        self.log.debug(partial_signed_1)
        assert_equal(partial_signed_1['complete'], False)  # node1 has only one key

        partial_signed_2 = self.nodes[2].signrawtransactionwithwallet(raw_tx, inputs)
        self.log.debug(partial_signed_2)
        assert_equal(partial_signed_2['complete'], False)  # node2 has only one key

        combined = self.nodes[2].combinerawtransaction([partial_signed_1['hex'], partial_signed_2['hex']])
        self.log.debug(combined)

        self.nodes[2].sendrawtransaction(combined)
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_all()

        assert_equal(self.nodes[0].getbalance(), bal + Decimal('50.00000000') + Decimal('2.19000000'))

    # ------------------------------------------------------------------
    # decoderawtransaction
    # ------------------------------------------------------------------

    def test_decoderawtransaction(self):
        node = self.nodes[0]

        # Witness transaction, decoded as witness.
        witness_tx = "010000000001010000000000000072c1a6a246ae63f74f931e8365e15a089c68d61900000000000000000000ffffffff0100e1f50500000000000102616100000000"
        decoded = node.decoderawtransaction(witness_tx, True)
        assert_equal(decoded['vout'][0]['value'], Decimal('1.00000000'))
        # Forcing a non-witness decode of a witness tx should fail.
        assert_raises_rpc_error(-22, 'TX decode failed', node.decoderawtransaction, witness_tx, False)

        # Non-witness transaction, decoded as non-witness.
        nonwitness_tx = "01000000010000000000000072c1a6a246ae63f74f931e8365e15a089c68d61900000000000000000000ffffffff0100e1f505000000000000000000"
        decoded = node.decoderawtransaction(nonwitness_tx, False)
        assert_equal(decoded['vout'][0]['value'], Decimal('1.00000000'))

        # A known ambiguous transaction on-chain: could parse as witness or
        # non-witness, and the witness interpretation must win.
        # See https://github.com/bitcoin/bitcoin/issues/20579
        ambiguous_tx = (
            "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff4b03c68"
            "708046ff8415c622f4254432e434f4d2ffabe6d6de1965d02c68f928e5b244ab1965115a36f56eb997633c7f690124b"
            "bf43644e23080000000ca3d3af6d005a65ff0200fd00000000ffffffff03f4c1fb4b00000000160014"
            "97cfc76442fe717f2a3f0cc9c175f7561b661997000000000000000026"
            "6a24aa21a9ed957d1036a80343e0d1b659497e1b48a38ebe876a056d45965fac4a85cda84e19000000000000000029"
            "52534b424c4f434b3a8e092581ab01986cbadc84f4b43f4fa4bb9e7a2e2a0caf9b7cf64d939028e22c012000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        decoded = node.decoderawtransaction(ambiguous_tx)
        decoded_wit = node.decoderawtransaction(ambiguous_tx, True)
        assert_raises_rpc_error(-22, 'TX decode failed', node.decoderawtransaction, ambiguous_tx, False)
        assert_equal(decoded, decoded_wit)  # the witness interpretation should be chosen
        assert_equal(
            decoded['vin'][0]['coinbase'],
            "03c68708046ff8415c622f4254432e434f4d2ffabe6d6de1965d02c68f928e5b244ab1965115a36f56eb997633c7f6"
            "90124bbf43644e23080000000ca3d3af6d005a65ff0200fd00000000",
        )

    # ------------------------------------------------------------------
    # Basic sign/getrawtransaction round-trip and its parameter validation
    # ------------------------------------------------------------------

    def test_basic_signrawtransaction_and_getrawtransaction(self):
        addr = self.nodes[1].getnewaddress()
        txid = self.nodes[0].sendtoaddress(addr, 10)
        self.nodes[0].generate(1)
        self.sync_all()

        vout = find_vout_for_address(self.nodes[1], txid, addr)
        raw_tx = self.nodes[1].createrawtransaction(
            [{'txid': txid, 'vout': vout}], {self.nodes[1].getnewaddress(): 9.999},
        )
        signed = self.nodes[1].signrawtransactionwithwallet(raw_tx)
        sent_txid = self.nodes[1].sendrawtransaction(signed['hex'])
        self.nodes[0].generate(1)
        self.sync_all()

        node = self.nodes[0]

        # 1. Only supply txid.
        assert_equal(node.getrawtransaction(sent_txid), signed['hex'])
        # 2. txid + 0 (non-verbose).
        assert_equal(node.getrawtransaction(sent_txid, 0), signed['hex'])
        # 3. txid + False (non-verbose).
        assert_equal(node.getrawtransaction(sent_txid, False), signed['hex'])
        # 4. txid + 1 (verbose). Only the "hex" field is checked so this test
        #    doesn't need updating every time the verbose output format changes.
        assert_equal(node.getrawtransaction(sent_txid, 1)["hex"], signed['hex'])
        # 5. txid + True (verbose).
        assert_equal(node.getrawtransaction(sent_txid, True)["hex"], signed['hex'])
        # 6. Invalid: txid + string "Flase" (typo'd bool).
        assert_raises_rpc_error(-1, "not a boolean", node.getrawtransaction, sent_txid, "Flase")
        # 7. Invalid: txid + empty array.
        assert_raises_rpc_error(-1, "not a boolean", node.getrawtransaction, sent_txid, [])
        # 8. Invalid: txid + empty dict.
        assert_raises_rpc_error(-1, "not a boolean", node.getrawtransaction, sent_txid, {})

    # ------------------------------------------------------------------
    # Sequence number validation
    # ------------------------------------------------------------------

    def test_sequence_number_validation(self):
        node = self.nodes[0]

        # In range: sequence number round-trips through create + decode.
        inputs = [{'txid': PLACEHOLDER_TXID, 'vout': 1, 'sequence': 1000}]
        outputs = {node.getnewaddress(): 1}
        raw_tx = node.createrawtransaction(inputs, outputs)
        decoded = node.decoderawtransaction(raw_tx)
        assert_equal(decoded['vin'][0]['sequence'], 1000)

        # Out of range: negative.
        inputs = [{'txid': PLACEHOLDER_TXID, 'vout': 1, 'sequence': -1}]
        assert_raises_rpc_error(
            -8, 'Invalid parameter, sequence number is out of range',
            node.createrawtransaction, inputs, {node.getnewaddress(): 1},
        )

        # Out of range: above uint32 max.
        inputs = [{'txid': PLACEHOLDER_TXID, 'vout': 1, 'sequence': 4294967296}]
        assert_raises_rpc_error(
            -8, 'Invalid parameter, sequence number is out of range',
            node.createrawtransaction, inputs, {node.getnewaddress(): 1},
        )

        # In range: exactly uint32 max - 1.
        inputs = [{'txid': PLACEHOLDER_TXID, 'vout': 1, 'sequence': 4294967294}]
        raw_tx = node.createrawtransaction(inputs, {node.getnewaddress(): 1})
        decoded = node.decoderawtransaction(raw_tx)
        assert_equal(decoded['vin'][0]['sequence'], 4294967294)

    # ------------------------------------------------------------------
    # Transaction version number bounds
    # ------------------------------------------------------------------

    def test_transaction_version_number_bounds(self):
        node = self.nodes[0]

        # Minimum version that fits in a signed 32-bit integer. Since
        # transaction version is unsigned, this should wrap to its
        # unsigned equivalent.
        tx = CTransaction()
        tx.nVersion = -0x80000000
        decoded = node.decoderawtransaction(ToHex(tx))
        assert_equal(decoded['version'], 0x80000000)

        # Maximum version that fits in a signed 32-bit integer.
        tx = CTransaction()
        tx.nVersion = 0x7fffffff
        decoded = node.decoderawtransaction(ToHex(tx))
        assert_equal(decoded['version'], 0x7fffffff)

    # ------------------------------------------------------------------
    # sendrawtransaction / testmempoolaccept with maxfeerate
    # ------------------------------------------------------------------

    def test_sendrawtransaction_maxfeerate(self):
        self.log.info('sendrawtransaction/testmempoolaccept with maxfeerate')

        # (fee_sats, output_amount, description) -- both scenarios build a
        # ~100-byte transaction, so the resulting fee rate is roughly
        # fee_sats sat/byte.
        self.check_maxfeerate_scenario(
            fee_sats=10_000, output_amount=Decimal("0.99990000"), maxfeerate="0.00001000",
        )
        self.check_maxfeerate_scenario(
            fee_sats=2_000_000, output_amount=Decimal("0.98000000"), maxfeerate=None,
        )

    def check_maxfeerate_scenario(self, fee_sats, output_amount, maxfeerate):
        """Send a tx whose fee rate exceeds a low maxfeerate cap, confirm it's
        rejected by testmempoolaccept/sendrawtransaction, then confirm both
        succeed once given a high-enough maxfeerate to allow it through.

        `maxfeerate`, if given, is the explicit cap used for the "reject"
        half of the check; otherwise the RPCs' default cap is used.
        """
        txid = self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 1.0)
        raw_tx = self.nodes[0].getrawtransaction(txid, True)
        vout = next(o for o in raw_tx['vout'] if o['value'] == Decimal('1.00000000'))
        self.sync_all()

        inputs = [{"txid": txid, "vout": vout['n']}]
        outputs = {self.nodes[0].getnewaddress(): output_amount}
        raw_tx = self.nodes[2].createrawtransaction(inputs, outputs)
        signed = self.nodes[2].signrawtransactionwithwallet(raw_tx)
        assert_equal(signed['complete'], True)

        # The fee rate should land well above what a normal cap would allow,
        # so testmempoolaccept should reject it under the given cap.
        reject_kwargs = {} if maxfeerate is None else {"maxfeerate": maxfeerate}
        testres = self.nodes[2].testmempoolaccept([signed['hex']], **reject_kwargs)[0]
        assert_equal(testres['allowed'], False)
        assert_equal(testres['reject-reason'], 'max-fee-exceeded')

        send_reject_args = [signed['hex']] if maxfeerate is None else [signed['hex'], maxfeerate]
        assert_raises_rpc_error(
            -25, 'Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)',
            self.nodes[2].sendrawtransaction, *send_reject_args,
        )

        # With a cap generous enough to cover this fee rate (or the default
        # cap, for the small-fee case where it's already generous enough),
        # both calls should succeed.
        is_large_fee = fee_sats >= 100_000
        accept_kwargs = {"maxfeerate": "0.20000000"} if is_large_fee else {}

        testres = self.nodes[2].testmempoolaccept(rawtxs=[signed['hex']], **accept_kwargs)[0]
        assert_equal(testres['allowed'], True)
        self.nodes[2].sendrawtransaction(hexstring=signed['hex'], **accept_kwargs)


if __name__ == '__main__':
    RawTransactionsTest().main()
