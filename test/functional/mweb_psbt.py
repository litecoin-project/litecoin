#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tests PSBT functionality for MWEB transactions."""

from decimal import Decimal

from test_framework.psbt import (
    PSBT,
    PSBT_GLOBAL_MWEB_TX_OFFSET,
    PSBT_GLOBAL_MWEB_TX_STEALTH_OFFSET,
    PSBT_GLOBAL_TX_MODIFIABLE,
    PSBT_IN_MWEB_ADDR_DESCRIPTOR,
    PSBT_IN_MWEB_COMMIT,
    PSBT_IN_MWEB_EXTRA_DATA,
    PSBT_IN_MWEB_FEATURES,
    PSBT_IN_MWEB_INPUT_SIG,
    PSBT_IN_MWEB_OUTPUT_PUBKEY,
    PSBT_IN_MWEB_KEY_EXCHANGE_PK,
    PSBT_KERN_EXTRA_DATA,
    PSBT_KERN_FEATURES,
    PSBT_KERN_PEGOUT,
    PSBT_KERN_SIG,
    PSBT_OUT_MWEB_EXTRA_DATA,
    PSBT_OUT_MWEB_FEATURES,
    PSBT_OUT_MWEB_SIG,
    PSBT_OUT_SCRIPT,
)
from test_framework.test_framework import LitecoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class MWEBPsbtTest(LitecoinTestFramework):
    MWEB_BYTES_PER_WEIGHT = 42
    MWEB_KERNEL_WITH_STEALTH_WEIGHT = 3
    MWEB_BASE_OUTPUT_WEIGHT = 17
    MWEB_STANDARD_OUTPUT_WEIGHT = 18
    MWEB_STANDARD_FIELDS_FEATURE_BIT = 0x01

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
        node0 = self.nodes[0]
        node1 = self.nodes[1]

        self.decode_tests()

        self.log.info("Setup MWEB chain with spendable MWEB funds")
        self.setup_mweb_chain(node0, pegin_amount=Decimal('10'))
        self.sync_blocks()

        self.log.info("Move MWEB funds to node1 so funding must use an MWEB input")
        node1_mweb_addr = node1.getnewaddress(address_type='mweb')
        node0_to_node1_txid = node0.sendtoaddress(node1_mweb_addr, Decimal('5'))
        node0_to_node1_hex = node0.getrawtransaction(node0_to_node1_txid)
        assert_raises_rpc_error(
            -8,
            "fundrawtransaction does not support MWEB transaction hex",
            node0.fundrawtransaction,
            node0_to_node1_hex,
        )
        self.generate(node0, 1, sync_fun=self.sync_all)

        utxos = node1.listunspent(addresses=[node1_mweb_addr])
        assert_equal(len(utxos), 1)

        self.test_mweb_raw_hex_rejected(node0, node1)
        self.test_mweb_psbtv0_creation_rejected(node0, node1)

        self.log.info("Create an MWEB-input PSBT and capture the original updater fields")
        recipient = node0.getnewaddress(address_type='mweb')
        funded = node1.walletcreatefundedpsbt([], {recipient: Decimal('2')})
        original_psbt = funded["psbt"]
        original_decoded = node0.decodepsbt(original_psbt)
        self.assert_kernel_count_and_features_decoded(original_decoded, original_psbt)

        mweb_input_index = next(i for i, txin in enumerate(original_decoded["inputs"]) if txin.get("mweb"))

        parsed = PSBT.from_base64(original_psbt)
        input_map = parsed.i[mweb_input_index].map
        original_address_descriptor = input_map[PSBT_IN_MWEB_ADDR_DESCRIPTOR]
        assert original_address_descriptor.startswith(b"mweb(")
        assert_equal(original_decoded["inputs"][mweb_input_index]["mweb"]["address_descriptor"], original_address_descriptor.decode())
        original_commit = input_map[PSBT_IN_MWEB_COMMIT]
        original_output_pubkey = input_map[PSBT_IN_MWEB_OUTPUT_PUBKEY]
        original_key_exchange_pk = input_map.get(PSBT_IN_MWEB_KEY_EXCHANGE_PK)
        del input_map[PSBT_IN_MWEB_COMMIT]
        del input_map[PSBT_IN_MWEB_OUTPUT_PUBKEY]
        had_key_exchange_pk = PSBT_IN_MWEB_KEY_EXCHANGE_PK in input_map
        if had_key_exchange_pk:
            del input_map[PSBT_IN_MWEB_KEY_EXCHANGE_PK]

        stripped_psbt = parsed.to_base64()
        stripped_input_map = PSBT.from_base64(stripped_psbt).i[mweb_input_index].map
        assert PSBT_IN_MWEB_COMMIT not in stripped_input_map
        assert PSBT_IN_MWEB_OUTPUT_PUBKEY not in stripped_input_map
        assert PSBT_IN_MWEB_KEY_EXCHANGE_PK not in stripped_input_map
        assert_equal(stripped_input_map[PSBT_IN_MWEB_ADDR_DESCRIPTOR], original_address_descriptor)

        self.log.info("utxoupdatepsbt restores MWEB input metadata from chain state")
        updated_psbt = node0.utxoupdatepsbt(stripped_psbt)
        updated_input_map = PSBT.from_base64(updated_psbt).i[mweb_input_index].map

        assert_equal(updated_input_map[PSBT_IN_MWEB_COMMIT], original_commit)
        assert_equal(updated_input_map[PSBT_IN_MWEB_OUTPUT_PUBKEY], original_output_pubkey)
        if had_key_exchange_pk:
            assert_equal(updated_input_map[PSBT_IN_MWEB_KEY_EXCHANGE_PK], original_key_exchange_pk)

        self.log.info("combinepsbt merges MWEB updater metadata")
        for combined_psbt in [
            node0.combinepsbt([stripped_psbt, updated_psbt]),
            node0.combinepsbt([updated_psbt, stripped_psbt]),
            node0.combinepsbt([original_psbt, updated_psbt]),
        ]:
            combined_input_map = PSBT.from_base64(combined_psbt).i[mweb_input_index].map
            assert_equal(combined_input_map[PSBT_IN_MWEB_COMMIT], original_commit)
            assert_equal(combined_input_map[PSBT_IN_MWEB_OUTPUT_PUBKEY], original_output_pubkey)

        self.test_mweb_components_are_included_in_global_next(node0, node1)
        self.test_mweb_pegout_indexes_are_honored(node0, node1)
        self.workflow_tests(node0, node1)

    def test_mweb_raw_hex_rejected(self, node0, node1):
        self.log.info("Raw transaction hex RPCs reject unsupported MWEB workflows")
        mweb_recipient = node0.getnewaddress(address_type='mweb')
        assert_raises_rpc_error(
            -8,
            "MWEB outputs cannot be represented in raw transaction hex",
            node0.createrawtransaction,
            [],
            {mweb_recipient: Decimal('1')},
        )

        raw_ltc_tx = node1.createrawtransaction([], {node0.getnewaddress(): Decimal('1')})
        assert_raises_rpc_error(
            -8,
            "fundrawtransaction cannot return MWEB transaction hex",
            node1.fundrawtransaction,
            raw_ltc_tx,
        )

    def workflow_tests(self, node0, node1):
        self.log.info("combinepsbt rejects distinct MWEB-only transaction intents")
        psbt1 = node1.walletcreatefundedpsbt(
            [],
            {node0.getnewaddress(address_type='mweb'): Decimal('1')},
        )["psbt"]
        psbt2 = node1.walletcreatefundedpsbt(
            [],
            {node0.getnewaddress(address_type='mweb'): Decimal('1')},
        )["psbt"]
        assert_raises_rpc_error(-8, "PSBTs not compatible", node0.combinepsbt, [psbt1, psbt2])

        self.log.info("Build, sign, and broadcast an MWEB-to-MWEB PSBT")
        self.run_workflow_test(
            node0=node0,
            node1=node1,
            recipients={node0.getnewaddress(address_type='mweb'): Decimal('2')},
            expected_output_type='mweb',
        )

        self.log.info("Build, sign, and broadcast an MWEB pegout PSBT")
        self.run_workflow_test(
            node0=node0,
            node1=node1,
            recipients={node0.getnewaddress(address_type='bech32'): Decimal('1.5')},
            expected_output_type='script',
        )

        self.log.info("Build, sign, and finalize an MWEB PSBT with extra_data")
        self.run_extra_data_workflow_test(node0, node1)

    def test_mweb_psbtv0_creation_rejected(self, node0, node1):
        self.log.info("PSBTv0 creation rejects MWEB components")
        mweb_recipient = node0.getnewaddress(address_type='mweb')
        assert_raises_rpc_error(
            -8,
            "MWEB PSBTs require PSBT version 2",
            node0.createpsbt,
            [],
            {mweb_recipient: Decimal('1')},
            0,
            False,
            0,
        )
        assert_raises_rpc_error(
            -8,
            "MWEB PSBTs require PSBT version 2",
            node1.walletcreatefundedpsbt,
            [],
            {mweb_recipient: Decimal('1')},
            0,
            {},
            True,
            0,
        )

    def run_extra_data_workflow_test(self, node0, node1):
        recipient = node0.getnewaddress(address_type='mweb')
        amount = Decimal('0.5')

        funded = node1.walletcreatefundedpsbt(
            [],
            {recipient: amount},
            0,
            {"fee_rate": 10},
        )
        decoded = node0.decodepsbt(funded["psbt"])
        mweb_input_index = next(i for i, txin in enumerate(decoded["inputs"]) if txin.get("mweb"))
        mweb_output_index = self.find_recipient_output_index(decoded, recipient, 'mweb')

        input_extra = bytes.fromhex("51")
        output_extra = bytes.fromhex("52")
        kernel_extra = bytes.fromhex("53")

        parsed = PSBT.from_base64(funded["psbt"])
        parsed.i[mweb_input_index].map[PSBT_IN_MWEB_EXTRA_DATA] = input_extra
        parsed.o[mweb_output_index].map[PSBT_OUT_MWEB_EXTRA_DATA] = output_extra
        assert len(parsed.k) > 0
        parsed.k[0].map[PSBT_KERN_EXTRA_DATA] = kernel_extra

        extra_data_psbt = parsed.to_base64()
        extra_data_decoded = node0.decodepsbt(extra_data_psbt)
        self.assert_kernel_count_and_features_decoded(extra_data_decoded, extra_data_psbt)
        assert_equal(extra_data_decoded["inputs"][mweb_input_index]["mweb"]["extra_data"], input_extra.hex())
        assert_equal(extra_data_decoded["outputs"][mweb_output_index]["mweb"]["extra_data"], output_extra.hex())
        assert_equal(extra_data_decoded["kernels"][0]["extra_data"], kernel_extra.hex())

        signed = node1.walletprocesspsbt(extra_data_psbt, True, "ALL", True, False)
        assert signed["complete"]

        signed_decoded = node0.decodepsbt(signed["psbt"])
        self.assert_kernel_count_and_features_decoded(signed_decoded, signed["psbt"])
        assert_equal(signed_decoded["inputs"][mweb_input_index]["mweb"]["extra_data"], input_extra.hex())
        assert_equal(signed_decoded["outputs"][mweb_output_index]["mweb"]["extra_data"], output_extra.hex())
        assert_equal(signed_decoded["kernels"][0]["extra_data"], kernel_extra.hex())
        assert signed_decoded["kernels"][0]["features"] & 0x20

        signed_parsed = PSBT.from_base64(signed["psbt"])
        assert signed_parsed.i[mweb_input_index].map[PSBT_IN_MWEB_FEATURES][0] & 0x02
        assert signed_parsed.o[mweb_output_index].map[PSBT_OUT_MWEB_FEATURES][0] & 0x02
        assert signed_parsed.k[0].map[PSBT_KERN_FEATURES][0] & 0x20

        conflicting = PSBT.from_base64(signed["psbt"])
        conflicting.o[mweb_output_index].map[PSBT_OUT_MWEB_EXTRA_DATA] = bytes.fromhex("53")
        assert_raises_rpc_error(-8, "PSBTs not compatible", node0.combinepsbt, [signed["psbt"], conflicting.to_base64()])

        finalized = node0.finalizepsbt(signed["psbt"])
        assert finalized["complete"]
        assert_raises_rpc_error(-26, "non-standard-mweb-tx", node0.sendrawtransaction, finalized["hex"])

    def test_mweb_components_are_included_in_global_next(self, node0, node1):
        self.log.info("Global next accounts for MWEB components without MWEB inputs")

        pegin_recipient = node1.getnewaddress(address_type='mweb')
        ltc_utxo = next(utxo for utxo in node0.listunspent() if "mweb" not in utxo["address"])
        funded = node0.walletcreatefundedpsbt(
            [{"txid": ltc_utxo["txid"], "vout": ltc_utxo["vout"]}],
            {pegin_recipient: Decimal('1')},
            0,
            {"add_inputs": False},
        )

        signed = node0.walletprocesspsbt(funded["psbt"], True, "ALL", True, True)
        assert signed["complete"]
        self.assert_combinepsbt_complete(node0, funded["psbt"], signed["psbt"])

        signed_output_scripts = [output.map.get(PSBT_OUT_SCRIPT) for output in PSBT.from_base64(signed["psbt"]).o]
        for combined_psbt in [
            node0.combinepsbt([funded["psbt"], signed["psbt"]]),
            node0.combinepsbt([signed["psbt"], funded["psbt"]]),
        ]:
            combined_output_scripts = [output.map.get(PSBT_OUT_SCRIPT) for output in PSBT.from_base64(combined_psbt).o]
            assert_equal(combined_output_scripts, signed_output_scripts)

        signed_analysis = node0.analyzepsbt(signed["psbt"])
        signed_decoded = node0.decodepsbt(signed["psbt"])
        assert "mweb_next" not in signed_analysis
        assert_equal(signed_analysis["next"], "extractor")
        assert_equal(signed_analysis["fee"], funded["fee"])
        assert_equal(signed_analysis["estimated_mweb_weight"], self.expected_mweb_weight(signed_decoded))
        assert all(input_analysis["next"] == "extractor" for input_analysis in signed_analysis["inputs"])

        parsed = PSBT.from_base64(signed["psbt"])
        assert PSBT_GLOBAL_MWEB_TX_OFFSET in parsed.g.map
        assert PSBT_GLOBAL_MWEB_TX_STEALTH_OFFSET in parsed.g.map
        del parsed.g.map[PSBT_GLOBAL_MWEB_TX_OFFSET]

        missing_offset_analysis = node0.analyzepsbt(parsed.to_base64())
        assert "mweb_next" not in missing_offset_analysis
        assert_equal(missing_offset_analysis["next"], "signer")
        assert all(input_analysis["next"] == "extractor" for input_analysis in missing_offset_analysis["inputs"])

    def test_mweb_pegout_indexes_are_honored(self, node0, node1):
        self.log.info("MWEB kernel pegout parsing uses keydata indexes, not wire order")

        funded = node1.walletcreatefundedpsbt(
            [],
            {
                node0.getnewaddress(address_type='bech32'): Decimal('0.7'),
                node0.getnewaddress(address_type='bech32'): Decimal('0.8'),
            },
        )
        decoded = node0.decodepsbt(funded["psbt"])
        original_pegouts = decoded["kernels"][0]["pegouts"]
        assert_equal(len(original_pegouts), 2)

        parsed = PSBT.from_base64(funded["psbt"])
        kernel_map = parsed.k[0].map
        pegout_entries = [(key, value) for key, value in kernel_map.items() if self.is_kernel_pegout_key(key)]
        assert_equal(len(pegout_entries), 2)
        assert all(isinstance(key, bytes) and len(key) > 1 for key, _ in pegout_entries)

        reordered_map = {}
        inserted_reversed_pegouts = False
        for key, value in kernel_map.items():
            if self.is_kernel_pegout_key(key):
                if not inserted_reversed_pegouts:
                    for pegout_key, pegout_value in reversed(pegout_entries):
                        reordered_map[pegout_key] = pegout_value
                    inserted_reversed_pegouts = True
                continue
            reordered_map[key] = value
        parsed.k[0].map = reordered_map

        reordered_decoded = node0.decodepsbt(parsed.to_base64())
        assert_equal(reordered_decoded["kernels"][0]["pegouts"], original_pegouts)

        malformed = PSBT.from_base64(funded["psbt"])
        malformed_pegout_key, malformed_pegout_value = pegout_entries[0]
        del malformed.k[0].map[malformed_pegout_key]
        malformed.k[0].map[PSBT_KERN_PEGOUT] = malformed_pegout_value
        assert_raises_rpc_error(
            -22,
            "TX decode failed Kernel pegout key is missing index",
            node0.decodepsbt,
            malformed.to_base64(),
        )

    def run_workflow_test(self, node0, node1, recipients, expected_output_type):
        recipient, amount = next(iter(recipients.items()))

        funded = node1.walletcreatefundedpsbt([], recipients)
        unsigned_psbt = funded["psbt"]
        unsigned_decoded = node0.decodepsbt(unsigned_psbt)
        unsigned_analysis = node0.analyzepsbt(unsigned_psbt)

        self.assert_unsigned_mweb_psbt(unsigned_decoded, unsigned_analysis, recipient, amount, expected_output_type)

        unsigned_modifiable = PSBT.from_base64(unsigned_psbt)
        unsigned_modifiable.g.map[PSBT_GLOBAL_TX_MODIFIABLE] = b"\x03"
        unsigned_modifiable_psbt = unsigned_modifiable.to_base64()

        signed = node1.walletprocesspsbt(unsigned_modifiable_psbt, True, "ALL", True, False)
        assert signed["complete"]

        signed_psbt = signed["psbt"]
        self.assert_combinepsbt_complete(node0, unsigned_psbt, signed_psbt)
        self.assert_combinepsbt_complete(node0, unsigned_modifiable_psbt, signed_psbt)
        self.assert_mweb_modifiability_cleared(node0, signed_psbt, unsigned_modifiable_psbt)
        self.assert_conflicting_mweb_global_rejected(node0, signed_psbt)

        signed_decoded = node0.decodepsbt(signed_psbt)
        signed_analysis = node0.analyzepsbt(signed_psbt)

        self.assert_signed_mweb_psbt(unsigned_decoded, signed_decoded, signed_analysis, recipient, amount, expected_output_type)
        if expected_output_type == 'mweb':
            self.assert_tampered_mweb_signatures_not_finalized(node0, signed_psbt)

        finalized = node0.finalizepsbt(signed_psbt)
        assert finalized["complete"]
        txid = node0.sendrawtransaction(finalized["hex"])
        self.generate(node0, 1, sync_fun=self.sync_all)

        if expected_output_type == 'mweb':
            utxos = node0.listunspent(addresses=[recipient])
            assert_equal(len(utxos), 1)
            assert_equal(utxos[0]["amount"], amount)
            assert_equal(utxos[0]["confirmations"], 1)
        else:
            received = node0.listreceivedbyaddress(minconf=0, address_filter=recipient)
            assert_equal(len(received), 1)
            assert_equal(received[0]["amount"], amount)
            assert_equal(received[0]["confirmations"], 1)

    def assert_combinepsbt_complete(self, node, unsigned_psbt, signed_psbt):
        for psbts in ([unsigned_psbt, signed_psbt], [signed_psbt, unsigned_psbt]):
            combined = node.combinepsbt(psbts)
            finalized = node.finalizepsbt(combined)
            assert finalized["complete"]

    def assert_kernel_count_and_features_decoded(self, decoded_psbt, psbt_base64):
        parsed = PSBT.from_base64(psbt_base64)
        assert_equal(decoded_psbt["kernel_count"], parsed.kernel_count)
        assert_equal(decoded_psbt["kernel_count"], len(decoded_psbt["kernels"]))
        assert_equal(decoded_psbt["kernel_count"], len(parsed.k))

        for i, kernel in enumerate(parsed.k):
            if PSBT_KERN_FEATURES in kernel.map:
                assert_equal(decoded_psbt["kernels"][i]["features"], kernel.map[PSBT_KERN_FEATURES][0])
            else:
                assert "features" not in decoded_psbt["kernels"][i]

    def assert_conflicting_mweb_global_rejected(self, node, signed_psbt):
        parsed = PSBT.from_base64(signed_psbt)
        offset = bytearray(parsed.g.map[PSBT_GLOBAL_MWEB_TX_OFFSET])
        offset[0] ^= 0x01
        parsed.g.map[PSBT_GLOBAL_MWEB_TX_OFFSET] = bytes(offset)
        assert_raises_rpc_error(-8, "PSBTs not compatible", node.combinepsbt, [signed_psbt, parsed.to_base64()])

    def assert_tampered_mweb_signatures_not_finalized(self, node, signed_psbt):
        for maps_getter, key in [
            (lambda psbt: psbt.i, PSBT_IN_MWEB_INPUT_SIG),
            (lambda psbt: psbt.o, PSBT_OUT_MWEB_SIG),
            (lambda psbt: psbt.k, PSBT_KERN_SIG),
        ]:
            parsed = PSBT.from_base64(signed_psbt)
            self.tamper_first_psbt_field(maps_getter(parsed), key)
            finalized = node.finalizepsbt(parsed.to_base64())
            assert_equal(finalized["complete"], False)
            assert "psbt" in finalized
            assert "hex" not in finalized

    def tamper_first_psbt_field(self, psbt_maps, key):
        for psbt_map in psbt_maps:
            if key not in psbt_map.map:
                continue

            value = bytearray(psbt_map.map[key])
            assert len(value) > 0
            value[-1] ^= 0x01
            psbt_map.map[key] = bytes(value)
            return

        raise AssertionError(f"Expected PSBT field {key} not found")

    def assert_mweb_modifiability_cleared(self, node, signed_psbt, unsigned_modifiable_psbt):
        signed_map = PSBT.from_base64(signed_psbt).g.map
        assert_equal(signed_map[PSBT_GLOBAL_TX_MODIFIABLE], b"\x00")

        signed_decoded = node.decodepsbt(signed_psbt)
        assert_equal(signed_decoded["inputs_modifiable"], False)
        assert_equal(signed_decoded["outputs_modifiable"], False)
        assert_equal(signed_decoded["has_sighash_single"], False)

        for combined in [
            node.combinepsbt([unsigned_modifiable_psbt, signed_psbt]),
            node.combinepsbt([signed_psbt, unsigned_modifiable_psbt]),
        ]:
            combined_map = PSBT.from_base64(combined).g.map
            assert_equal(combined_map[PSBT_GLOBAL_TX_MODIFIABLE], b"\x00")

    def is_kernel_pegout_key(self, key):
        return isinstance(key, bytes) and len(key) > 0 and key[0] == PSBT_KERN_PEGOUT

    def assert_unsigned_mweb_psbt(self, decoded_psbt, analysis, recipient, amount, expected_output_type):
        self.assert_mweb_analysis(analysis, expected_input_role='signer', expected_next='signer', expected_is_final=False)
        assert_equal(analysis["estimated_mweb_weight"], self.expected_mweb_weight(decoded_psbt))

        mweb_inputs = [txin for txin in decoded_psbt["inputs"] if txin.get("mweb")]
        assert_equal(len(mweb_inputs), 1)
        assert "signature" not in mweb_inputs[0]["mweb"]
        assert mweb_inputs[0]["mweb"]["address_descriptor"].startswith("mweb(")

        if expected_output_type == 'mweb':
            recipient_output = self.find_recipient_output(decoded_psbt, recipient, expected_output_type)
            assert_equal(recipient_output["amount"], amount)
        else:
            assert "pegouts" in decoded_psbt["kernels"][0]
            assert_equal(decoded_psbt["kernels"][0]["pegouts"][0]["scriptPubKey"]["address"], recipient)
            assert_equal(decoded_psbt["kernels"][0]["pegouts"][0]["amount"], self.to_litoshis(amount))

    def assert_signed_mweb_psbt(self, unsigned_decoded, decoded_psbt, analysis, recipient, amount, expected_output_type):
        self.assert_mweb_analysis(analysis, expected_input_role='extractor', expected_next='extractor', expected_is_final=True)
        assert_equal(analysis["estimated_mweb_weight"], self.expected_mweb_weight(decoded_psbt))

        unsigned_input = next(txin["mweb"] for txin in unsigned_decoded["inputs"] if txin.get("mweb"))
        signed_input = next(txin["mweb"] for txin in decoded_psbt["inputs"] if txin.get("mweb"))

        assert_equal(signed_input["output_id"], unsigned_input["output_id"])
        assert_equal(signed_input["output_commit"], unsigned_input["output_commit"])
        assert_equal(signed_input["output_pubkey"], unsigned_input["output_pubkey"])
        assert_equal(signed_input["address_descriptor"], unsigned_input["address_descriptor"])
        assert "signature" in signed_input
        assert "amount" in signed_input

        assert "mweb_tx_offset" in decoded_psbt
        assert "mweb_stealth_offset" in decoded_psbt

        if expected_output_type == 'mweb':
            recipient_output = self.find_recipient_output(decoded_psbt, recipient, expected_output_type)
            assert_equal(recipient_output["amount"], amount)

        mweb_outputs = [output["mweb"] for output in decoded_psbt["outputs"] if output.get("mweb")]
        assert len(mweb_outputs) > 0
        for mweb_output in mweb_outputs:
            assert "output_commit" in mweb_output
            assert "sender_pubkey" in mweb_output
            assert "output_pubkey" in mweb_output
            assert "rangeproof" in mweb_output
            assert "sig" in mweb_output

        assert len(decoded_psbt["kernels"]) > 0
        assert "signature" in decoded_psbt["kernels"][0]
        if expected_output_type == 'script':
            assert "pegouts" in decoded_psbt["kernels"][0]
            assert_equal(decoded_psbt["kernels"][0]["pegouts"][0]["scriptPubKey"]["address"], recipient)
            assert_equal(decoded_psbt["kernels"][0]["pegouts"][0]["amount"], self.to_litoshis(amount))

    def assert_mweb_analysis(self, analysis, expected_input_role, expected_next, expected_is_final):
        assert "mweb_next" not in analysis
        assert_equal(analysis["next"], expected_next)
        assert_equal(len(analysis["inputs"]), 1)
        assert_equal(analysis["inputs"][0]["has_utxo"], False)
        assert_equal(analysis["inputs"][0]["is_final"], expected_is_final)
        assert_equal(analysis["inputs"][0]["next"], expected_input_role)

    def extra_data_weight(self, hex_str):
        return ((len(hex_str) // 2) + self.MWEB_BYTES_PER_WEIGHT - 1) // self.MWEB_BYTES_PER_WEIGHT

    def expected_mweb_weight(self, decoded_psbt):
        has_mweb_components = False
        weight = 0

        for txin in decoded_psbt["inputs"]:
            mweb = txin.get("mweb")
            if not mweb:
                continue
            has_mweb_components = True
            weight += self.extra_data_weight(mweb.get("extra_data", ""))

        for output in decoded_psbt["outputs"]:
            mweb = output.get("mweb")
            if not mweb:
                continue
            has_mweb_components = True
            standard_fields = (
                "features" not in mweb or
                mweb["features"] & self.MWEB_STANDARD_FIELDS_FEATURE_BIT
            )
            weight += self.MWEB_STANDARD_OUTPUT_WEIGHT if standard_fields else self.MWEB_BASE_OUTPUT_WEIGHT
            weight += self.extra_data_weight(mweb.get("extra_data", ""))

        kernels = decoded_psbt["kernels"]
        if kernels:
            has_mweb_components = True
            for kernel in kernels:
                weight += self.MWEB_KERNEL_WITH_STEALTH_WEIGHT
                weight += self.extra_data_weight(kernel.get("extra_data", ""))
                for pegout in kernel.get("pegouts", []):
                    weight += self.extra_data_weight(pegout["scriptPubKey"]["hex"])
        elif has_mweb_components:
            weight += self.MWEB_KERNEL_WITH_STEALTH_WEIGHT

        return weight

    def find_recipient_output(self, decoded_psbt, recipient, expected_output_type):
        return decoded_psbt["outputs"][self.find_recipient_output_index(decoded_psbt, recipient, expected_output_type)]

    def find_recipient_output_index(self, decoded_psbt, recipient, expected_output_type):
        for i, output in enumerate(decoded_psbt["outputs"]):
            if expected_output_type == 'mweb':
                mweb = output.get("mweb")
                if mweb and mweb.get("address") == recipient:
                    return i
            else:
                script = output.get("script")
                if script and script.get("address") == recipient:
                    return i

        raise AssertionError(f"Expected output for recipient {recipient} not found")

    def to_litoshis(self, amount):
        return int(amount * Decimal('100000000'))

    def decode_tests(self):
        valid_psbt64 = [
            "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",
        ]
        for psbt_base64 in valid_psbt64:
            decoded_psbt = self.nodes[0].decodepsbt(psbt_base64)
            assert 'tx' in decoded_psbt

        for global_key, error in [
            (PSBT_GLOBAL_MWEB_TX_OFFSET, "PSBT_GLOBAL_MWEB_TX_OFFSET is not allowed in PSBTv0"),
            (PSBT_GLOBAL_MWEB_TX_STEALTH_OFFSET, "PSBT_GLOBAL_MWEB_TX_STEALTH_OFFSET is not allowed in PSBTv0"),
        ]:
            psbt = PSBT.from_base64(valid_psbt64[0])
            assert_equal(psbt.version, 0)
            psbt.g.map[global_key] = b"\x01" * 32
            assert_raises_rpc_error(-22, f"TX decode failed {error}", self.nodes[0].decodepsbt, psbt.to_base64())


if __name__ == '__main__':
    MWEBPsbtTest().main()
