// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/psbt.h>

#include <consensus/amount.h>
#include <key.h>
#include <mw/consensus/Weight.h>
#include <policy/feerate.h>
#include <psbt.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <test/util/psbt.h>
#include <test/util/psbt_vectors.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <optional>
#include <string>
#include <vector>

using namespace psbt_test;
using node::AnalyzePSBT;
using node::PSBTAnalysis;

BOOST_FIXTURE_TEST_SUITE(psbt_analysis_tests, BasicTestingSetup)

namespace {

//! A canonical PSBTv2 with one wpkh input and one output.
PartiallySignedTransaction WpkhPSBT(const CKey& key)
{
    PartiallySignedTransaction psbt;
    psbt.m_psbt_version = 2;
    psbt.tx_version = 2;

    PSBTInput input(2);
    input.prev_txid = uint256::ONE;
    input.prev_out = 0;
    psbt.inputs.push_back(input);

    PSBTOutput output(2);
    output.amount = 90'000;
    output.script = GetScriptForDestination(WitnessV0KeyHash(key.GetPubKey()));
    psbt.outputs.push_back(output);
    return psbt;
}

} // namespace

BOOST_AUTO_TEST_CASE(analyze_canonical_role_progression)
{
    const CKey key = ToCKey(TestSecret('7'));
    const CScript wpkh_script = GetScriptForDestination(WitnessV0KeyHash(key.GetPubKey()));

    // No UTXO: the Updater must attach one; no fee can be computed.
    {
        const PSBTAnalysis analysis = AnalyzePSBT(WpkhPSBT(key));
        BOOST_REQUIRE_EQUAL(analysis.inputs.size(), 1U);
        BOOST_CHECK(!analysis.inputs[0].has_utxo);
        BOOST_CHECK(!analysis.inputs[0].is_final);
        BOOST_CHECK(analysis.inputs[0].next == PSBTRole::UPDATER);
        BOOST_CHECK(analysis.next == PSBTRole::UPDATER);
        BOOST_CHECK(!analysis.fee.has_value());
    }

    // UTXO present but the signing pubkey is unknown (no BIP32 keypath):
    // more than signatures is missing, so the Updater is still next.
    PartiallySignedTransaction psbt = WpkhPSBT(key);
    psbt.inputs[0].witness_utxo = CTxOut(100'000, wpkh_script);
    {
        const PSBTAnalysis analysis = AnalyzePSBT(psbt);
        BOOST_CHECK(analysis.inputs[0].has_utxo);
        BOOST_CHECK(analysis.inputs[0].next == PSBTRole::UPDATER);
        BOOST_CHECK(!analysis.inputs[0].missing_pubkeys.empty());
    }

    // With the keypath attached only signatures are missing: Signer is next,
    // and the fee is computable.
    psbt.inputs[0].hd_keypaths.emplace(key.GetPubKey(), KeyOriginInfo{});
    {
        const PSBTAnalysis analysis = AnalyzePSBT(psbt);
        BOOST_CHECK(analysis.inputs[0].next == PSBTRole::SIGNER);
        BOOST_CHECK(!analysis.inputs[0].missing_sigs.empty());
        BOOST_CHECK(analysis.next == PSBTRole::SIGNER);
        BOOST_CHECK(analysis.fee == std::optional<CAmount>{10'000});
    }

    // With a partial signature the input can be finalized.
    FlatSigningProvider provider;
    provider.keys.emplace(key.GetPubKey().GetID(), key);
    provider.pubkeys.emplace(key.GetPubKey().GetID(), key.GetPubKey());
    {
        PartiallySignedTransaction partial = psbt;
        const PrecomputedTransactionData txdata = PrecomputePSBTData(partial);
        BOOST_REQUIRE(SignPSBTInput(provider, partial, 0, &txdata, SIGHASH_ALL, nullptr, /*finalize=*/false));
        const PSBTAnalysis analysis = AnalyzePSBT(partial);
        BOOST_CHECK(analysis.inputs[0].next == PSBTRole::FINALIZER);
        BOOST_CHECK(analysis.next == PSBTRole::FINALIZER);
    }

    // Finalized: nothing left but extraction.
    {
        PartiallySignedTransaction final_psbt = psbt;
        const PrecomputedTransactionData txdata = PrecomputePSBTData(final_psbt);
        BOOST_REQUIRE(SignPSBTInput(provider, final_psbt, 0, &txdata, SIGHASH_ALL, nullptr, /*finalize=*/true));
        const PSBTAnalysis analysis = AnalyzePSBT(final_psbt);
        BOOST_CHECK(analysis.inputs[0].is_final);
        BOOST_CHECK(analysis.inputs[0].next == PSBTRole::EXTRACTOR);
        BOOST_CHECK(analysis.next == PSBTRole::EXTRACTOR);
    }
}

BOOST_AUTO_TEST_CASE(analyze_mweb_role)
{
    const PartiallySignedTransaction full = DecodeHexPSBT(PSBT_MWEB_SIGNED);

    // Fully signed: every MWEB component shares the EXTRACTOR role.
    {
        const PSBTAnalysis analysis = AnalyzePSBT(full);
        BOOST_REQUIRE_EQUAL(analysis.inputs.size(), 1U);
        BOOST_CHECK(analysis.inputs[0].is_final);
        BOOST_CHECK(!analysis.inputs[0].has_utxo); // MWEB inputs carry no canonical UTXO
        BOOST_CHECK(analysis.inputs[0].next == PSBTRole::EXTRACTOR);
        BOOST_CHECK(analysis.next == PSBTRole::EXTRACTOR);
    }

    // Unsigned MWEB components: the (single, shared) MWEB role is SIGNER.
    {
        const PSBTAnalysis analysis = AnalyzePSBT(StripMWEBSignatures(full));
        BOOST_CHECK(!analysis.inputs[0].is_final);
        BOOST_CHECK(analysis.inputs[0].next == PSBTRole::SIGNER);
        BOOST_CHECK(analysis.next == PSBTRole::SIGNER);
    }

    // Signed but missing either global offset: still the Signer's job.
    {
        PartiallySignedTransaction no_offsets = full;
        no_offsets.mweb_tx_offset.reset();
        BOOST_CHECK(AnalyzePSBT(no_offsets).next == PSBTRole::SIGNER);
    }

    // MWEB components present but no kernel yet: still the Signer's job.
    {
        PartiallySignedTransaction no_kernels = full;
        no_kernels.kernels.clear();
        BOOST_CHECK(AnalyzePSBT(no_kernels).next == PSBTRole::SIGNER);
    }
}

BOOST_AUTO_TEST_CASE(analyze_mweb_amount_required)
{
    // An ID-only Creator PSBT still needs an updater to attach the
    // confidential amount. It is incomplete, not malformed.
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        psbt.inputs[0].mweb_amount.reset();
        const PSBTAnalysis analysis = AnalyzePSBT(psbt);
        BOOST_CHECK(analysis.error.empty());
        BOOST_REQUIRE_EQUAL(analysis.inputs.size(), 1U);
        BOOST_CHECK(analysis.inputs[0].next == PSBTRole::UPDATER);
        BOOST_CHECK(analysis.next == PSBTRole::UPDATER);
        BOOST_CHECK(!analysis.fee.has_value());
        BOOST_CHECK(!analysis.estimated_mweb_weight.has_value());
    }

    // Public coin metadata is also updater data.
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        psbt.inputs[0].mweb_output_commit.reset();
        const PSBTAnalysis analysis = AnalyzePSBT(psbt);
        BOOST_CHECK(analysis.error.empty());
        BOOST_CHECK(analysis.inputs[0].next == PSBTRole::UPDATER);
        BOOST_CHECK(analysis.next == PSBTRole::UPDATER);
    }

    // A supplied amount outside the monetary range is malformed.
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        psbt.inputs[0].mweb_amount = MAX_MONEY + 1;
        const PSBTAnalysis analysis = AnalyzePSBT(psbt);
        BOOST_CHECK_EQUAL(analysis.error, "PSBT is not valid. Input 0 has invalid value");
        BOOST_CHECK(analysis.next == PSBTRole::CREATOR);
    }
}

BOOST_AUTO_TEST_CASE(analyze_fee_and_weight)
{
    // MWEB-to-MWEB: fee = inputs - outputs.
    {
        const PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        const PSBTAnalysis analysis = AnalyzePSBT(psbt);
        BOOST_CHECK(analysis.fee == std::optional<CAmount>{10'000});

        // The estimated weight is composed from the consensus weight
        // primitives, one term per MWEB component.
        const bool standard_fields = !psbt.outputs[0].mweb_features.has_value() ||
                                     (*psbt.outputs[0].mweb_features & mw::OutputMessage::STANDARD_FIELDS_FEATURE_BIT);
        const size_t expected_weight =
            Weight::CalcInputWeight(psbt.inputs[0].mweb_extra_data) +
            Weight::CalcOutputWeight(standard_fields, psbt.outputs[0].mweb_extra_data) +
            Weight::CalcKernelWeight(/*has_stealth_excess=*/true, psbt.kernels[0].pegouts, psbt.kernels[0].extra_data);
        BOOST_CHECK(analysis.estimated_mweb_weight == std::optional<size_t>{expected_weight});

        BOOST_REQUIRE(analysis.estimated_vsize.has_value());
        BOOST_REQUIRE(analysis.estimated_feerate.has_value());
        BOOST_CHECK(*analysis.estimated_feerate == CFeeRate(10'000, *analysis.estimated_vsize, expected_weight));

        // With no kernels yet, one estimated kernel is added to the weight.
        PartiallySignedTransaction no_kernels = psbt;
        no_kernels.kernels.clear();
        const PSBTAnalysis no_kernel_analysis = AnalyzePSBT(no_kernels);
        const size_t expected_kernel_less =
            Weight::CalcInputWeight(psbt.inputs[0].mweb_extra_data) +
            Weight::CalcOutputWeight(standard_fields, psbt.outputs[0].mweb_extra_data) +
            Weight::CalcKernelWeight(/*has_stealth_excess=*/true, std::vector<PegOutCoin>{});
        BOOST_CHECK(no_kernel_analysis.estimated_mweb_weight == std::optional<size_t>{expected_kernel_less});
    }

    // Peg-out: fee = inputs - outputs - pegouts.
    {
        const PSBTAnalysis analysis = AnalyzePSBT(DecodeHexPSBT(PSBT_PEGOUT_SIGNED));
        BOOST_CHECK(analysis.fee == std::optional<CAmount>{10'000});
    }

    // Mixed peg-in: fee = canonical input + pegin - outputs, i.e. the
    // canonical fee (10k) plus the MWEB kernel fee (10k).
    {
        const PSBTAnalysis analysis = AnalyzePSBT(DecodeHexPSBT(PSBT_MIXED_SIGNED));
        BOOST_CHECK(analysis.fee == std::optional<CAmount>{20'000});
        BOOST_CHECK(analysis.next == PSBTRole::EXTRACTOR);
    }
}

BOOST_AUTO_TEST_CASE(analyze_invalid_amounts_and_utxos)
{
    // Output amount out of range
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        psbt.outputs[0].amount = MAX_MONEY + 1;
        BOOST_CHECK_EQUAL(AnalyzePSBT(psbt).error, "PSBT is not valid. Output amount invalid");
    }
    // Pegin amount out of range
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        psbt.kernels[0].pegin_amount = MAX_MONEY + 1;
        BOOST_CHECK_EQUAL(AnalyzePSBT(psbt).error, "PSBT is not valid. Pegin amount invalid");
    }
    // Pegout amount out of range
    {
        PartiallySignedTransaction psbt = DecodeHexPSBT(PSBT_MWEB_SIGNED);
        psbt.kernels[0].pegouts.emplace_back(MAX_MONEY + 1, CScript() << OP_TRUE);
        BOOST_CHECK_EQUAL(AnalyzePSBT(psbt).error, "PSBT is not valid. Pegout amount invalid");
    }
    // Unspendable UTXO
    {
        const CKey key = ToCKey(TestSecret('7'));
        PartiallySignedTransaction psbt = WpkhPSBT(key);
        psbt.inputs[0].witness_utxo = CTxOut(100'000, CScript() << OP_RETURN);
        BOOST_CHECK_EQUAL(AnalyzePSBT(psbt).error, "PSBT is not valid. Input 0 spends unspendable output");
    }
    // Previous transaction attached, but the outpoint index is out of range
    {
        CMutableTransaction prev;
        prev.vout.emplace_back(100'000, CScript() << OP_TRUE);
        const CTransactionRef prev_ref = MakeTransactionRef(prev);

        const CKey key = ToCKey(TestSecret('7'));
        PartiallySignedTransaction psbt = WpkhPSBT(key);
        psbt.inputs[0].non_witness_utxo = prev_ref;
        psbt.inputs[0].prev_txid = prev_ref->GetHash();
        psbt.inputs[0].prev_out = 5;
        BOOST_CHECK_EQUAL(AnalyzePSBT(psbt).error, "PSBT is not valid. Input 0 specifies invalid prevout");
    }
}

BOOST_AUTO_TEST_SUITE_END()
