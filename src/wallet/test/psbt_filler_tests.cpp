// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Tests for the PSBTFiller orchestration, driven through CWallet::FillPSBT
// (the thin delegator). The MWEB resolve/sign stages have direct coverage in
// mweb_psbt_tests.cpp; these tests verify the orchestration contract:
// updater-vs-signer behavior, the finalize flag, sighash handling, signed
// input accounting, and the MWEB-before-script signing order that the peg-in
// script rewrite requires.

#include <key_io.h>
#include <psbt.h>
#include <script/descriptor.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <uint256.h>
#include <test/util/psbt.h>
#include <util/strencodings.h>
#include <wallet/psbt_filler.h>
#include <wallet/test/psbt_test_utils.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>

namespace wallet {

using test::MWEBTestKeys;
using test::PeginTx;
using test::SignableMWEBPSBT;
using test::TestSecret;

BOOST_FIXTURE_TEST_SUITE(psbt_filler_tests, WalletTestingSetup)

namespace {

void ImportDescriptor(CWallet& wallet, const std::string& descriptor)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    FlatSigningProvider provider;
    std::string error;
    std::unique_ptr<Descriptor> desc = Parse(descriptor, provider, error, /*require_checksum=*/false);
    assert(desc);
    WalletDescriptor w_desc(std::move(desc), 0, 0, 10, 0);
    wallet.AddWalletDescriptor(w_desc, provider, "", false);
}

//! A mixed peg-in PSBT: one canonical wpkh input funding the peg-in vout
//! (placeholder script), one MWEB output, one peg-in kernel.
PartiallySignedTransaction MixedPeginPSBT(const CKey& canonical_key, const StealthAddress& recipient)
{
    CMutableTransaction mtx = PeginTx(recipient);
    mtx.vin.emplace_back(COutPoint(uint256::ONE, 0));

    PartiallySignedTransaction psbt(mtx, 2);
    psbt.inputs[0].witness_utxo = CTxOut(110'000, GetScriptForDestination(WitnessV0KeyHash(canonical_key.GetPubKey())));
    return psbt;
}

} // namespace

//! MWEB signing driven purely by descriptor-carried private keys: the wallet
//! holds no keys of its own, all key material rides in the PSBT.
BOOST_AUTO_TEST_CASE(fill_sign_mweb_via_descriptor_keys)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    const mw::Hash output_id = mw::Hash::ValueOf(1);
    const SecretKey shared_secret = TestSecret('b');

    PartiallySignedTransaction psbt = SignableMWEBPSBT(output_id, shared_secret, keys.Address(0));
    psbt.inputs[0].mweb_address_descriptor = keys.Descriptor(0);
    psbt.inputs[0].mweb_output_pubkey = keys.OutputPubKey(0, shared_secret);

    LOCK(m_wallet.cs_wallet);
    bool complete = false;
    size_t n_signed = 0;
    BOOST_REQUIRE_EQUAL(TransactionError::OK,
                        m_wallet.FillPSBT(psbt, complete, SIGHASH_ALL, /*sign=*/true, /*bip32derivs=*/false, &n_signed, /*finalize=*/true));

    BOOST_CHECK(complete);
    BOOST_CHECK(psbt.IsComplete());
    BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 0, nullptr));
    BOOST_CHECK(psbt.outputs[0].mweb_rangeproof.has_value());
    BOOST_CHECK(psbt.outputs[0].mweb_sig.has_value());
    BOOST_CHECK(psbt.kernels[0].sig.has_value());
    BOOST_CHECK(psbt.mweb_tx_offset.has_value());
    BOOST_CHECK(psbt.mweb_stealth_offset.has_value());

    // The MWEB input signed by the MWEB stage counts toward n_signed.
    BOOST_CHECK_EQUAL(n_signed, 1U);
}

//! An MWEB-only Creator PSBT does not need to know the confidential input
//! amount up front. Once updater metadata is present, the selected inputs and
//! requested outputs uniquely determine the kernel fee.
BOOST_AUTO_TEST_CASE(fill_infers_mweb_creator_kernel_fee)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    const mw::Hash output_id = mw::Hash::ValueOf(11);
    const SecretKey shared_secret = TestSecret('b');

    PartiallySignedTransaction psbt = SignableMWEBPSBT(output_id, shared_secret, keys.Address(0));
    psbt.kernels.clear();
    psbt.inputs[0].mweb_address_descriptor = keys.Descriptor(0);
    psbt.inputs[0].mweb_output_pubkey = keys.OutputPubKey(0, shared_secret);

    LOCK(m_wallet.cs_wallet);
    bool complete = true;
    BOOST_REQUIRE_EQUAL(TransactionError::OK,
                        m_wallet.FillPSBT(psbt, complete, SIGHASH_ALL, /*sign=*/false, /*bip32derivs=*/false));
    BOOST_CHECK(!complete);
    BOOST_REQUIRE_EQUAL(psbt.kernels.size(), 1U);
    BOOST_CHECK(psbt.kernels[0].fee == std::optional<CAmount>{10'000});
    BOOST_REQUIRE(psbt.kernels[0].features.has_value());
    BOOST_CHECK(*psbt.kernels[0].features & mw::Kernel::FEE_FEATURE_BIT);

    BOOST_REQUIRE_EQUAL(TransactionError::OK,
                        m_wallet.FillPSBT(psbt, complete, SIGHASH_ALL, /*sign=*/true, /*bip32derivs=*/false));
    BOOST_CHECK(complete);
    BOOST_CHECK(psbt.IsComplete());
}

BOOST_AUTO_TEST_CASE(fill_infers_mweb_creator_pegout_fee)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    const CKey recipient_key = MWEBTestKeys::ToCKey(TestSecret('7'));
    const mw::Hash output_id = mw::Hash::ValueOf(12);
    const SecretKey shared_secret = TestSecret('b');

    PartiallySignedTransaction psbt;
    psbt.m_psbt_version = 2;
    psbt.tx_version = 2;

    PSBTInput input(2);
    input.mweb_output_id = output_id;
    input.mweb_amount = 100'000;
    input.mweb_shared_secret = shared_secret;
    input.mweb_output_pubkey = keys.OutputPubKey(0, shared_secret);
    input.mweb_address_descriptor = keys.Descriptor(0);
    psbt.inputs.push_back(std::move(input));

    PSBTKernel kernel;
    kernel.pegouts.emplace_back(90'000, GetScriptForDestination(WitnessV0KeyHash(recipient_key.GetPubKey())));
    psbt.kernels.push_back(std::move(kernel));

    LOCK(m_wallet.cs_wallet);
    bool complete = false;
    BOOST_REQUIRE_EQUAL(TransactionError::OK,
                        m_wallet.FillPSBT(psbt, complete, SIGHASH_ALL, /*sign=*/true, /*bip32derivs=*/false));
    BOOST_CHECK(complete);
    BOOST_CHECK(psbt.kernels[0].fee == std::optional<CAmount>{10'000});
    BOOST_CHECK(psbt.IsComplete());
}

BOOST_AUTO_TEST_CASE(fill_rejects_mweb_creator_outputs_above_inputs)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    PartiallySignedTransaction psbt = SignableMWEBPSBT(mw::Hash::ValueOf(13), TestSecret('b'), keys.Address(0));
    psbt.kernels.clear();
    psbt.inputs[0].mweb_amount = 80'000;

    LOCK(m_wallet.cs_wallet);
    bool complete = false;
    BOOST_CHECK(m_wallet.FillPSBT(psbt, complete, SIGHASH_ALL, /*sign=*/false, /*bip32derivs=*/false) == TransactionError::INVALID_PSBT);
}

//! The stage-ordering contract: MWEB signing rewrites the peg-in script, and
//! the canonical signature (produced afterwards) commits to the rewrite.
BOOST_AUTO_TEST_CASE(fill_mixed_counts_n_signed)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    const CKey key = MWEBTestKeys::ToCKey(TestSecret('7'));

    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    ImportDescriptor(m_wallet, strprintf("wpkh(%s)", EncodeSecret(key)));

    PartiallySignedTransaction psbt = MixedPeginPSBT(key, keys.Address(0));

    bool complete = false;
    size_t n_signed = 0;
    BOOST_REQUIRE_EQUAL(TransactionError::OK,
                        m_wallet.FillPSBT(psbt, complete, SIGHASH_ALL, /*sign=*/true, /*bip32derivs=*/false, &n_signed, /*finalize=*/true));

    BOOST_CHECK(complete);
    BOOST_CHECK_EQUAL(n_signed, 1U); // the canonical wpkh input

    // The placeholder peg-in script was rewritten to the final kernel ID...
    mw::Hash script_kernel_id;
    BOOST_REQUIRE(psbt.outputs[0].script.has_value());
    BOOST_REQUIRE(psbt.outputs[0].script->IsMWEBPegin(&script_kernel_id));
    BOOST_CHECK(!script_kernel_id.IsZero());

    // ...and the canonical witness verifies against the REWRITTEN transaction:
    // the signature was necessarily produced after the MWEB stage.
    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbt);
    BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 0, &txdata));

    // End to end: the finalized transaction carries both sides.
    const util::Result<CMutableTransaction> final_tx = FinalizePSBT(psbt);
    BOOST_REQUIRE(bool{final_tx});
    BOOST_CHECK(!final_tx->vin[0].scriptWitness.IsNull());
    BOOST_CHECK(!final_tx->mweb_tx.IsNull());
}

BOOST_AUTO_TEST_CASE(fill_finalize_false_yields_partial_sigs)
{
    const CKey key = MWEBTestKeys::ToCKey(TestSecret('7'));
    const CScript wpkh_script = GetScriptForDestination(WitnessV0KeyHash(key.GetPubKey()));

    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    ImportDescriptor(m_wallet, strprintf("wpkh(%s)", EncodeSecret(key)));

    const auto make_psbt = [&] {
        PartiallySignedTransaction psbt;
        psbt.m_psbt_version = 2;
        psbt.tx_version = 2;
        PSBTInput input(2);
        input.prev_txid = uint256::ONE;
        input.prev_out = 0;
        input.witness_utxo = CTxOut(110'000, wpkh_script);
        psbt.inputs.push_back(input);
        PSBTOutput output(2);
        output.amount = 100'000;
        output.script = wpkh_script;
        psbt.outputs.push_back(output);
        return psbt;
    };

    // finalize=false: a partial signature only; FinalizePSBT completes it later.
    {
        PartiallySignedTransaction psbt = make_psbt();
        bool complete = true;
        BOOST_REQUIRE_EQUAL(TransactionError::OK,
                            m_wallet.FillPSBT(psbt, complete, SIGHASH_ALL, /*sign=*/true, /*bip32derivs=*/false, nullptr, /*finalize=*/false));
        BOOST_CHECK(!complete);
        BOOST_CHECK_EQUAL(psbt.inputs[0].partial_sigs.size(), 1U);
        BOOST_CHECK(psbt.inputs[0].final_script_witness.IsNull());

        BOOST_CHECK(bool{FinalizePSBT(psbt)});
        BOOST_CHECK(psbt.IsComplete());
    }
    // finalize=true: the final witness is produced directly.
    {
        PartiallySignedTransaction psbt = make_psbt();
        bool complete = false;
        BOOST_REQUIRE_EQUAL(TransactionError::OK,
                            m_wallet.FillPSBT(psbt, complete, SIGHASH_ALL, /*sign=*/true, /*bip32derivs=*/false, nullptr, /*finalize=*/true));
        BOOST_CHECK(complete);
        BOOST_CHECK(!psbt.inputs[0].final_script_witness.IsNull());
    }
}

//! sign=false is a pure Updater pass: metadata may be attached but no
//! signatures are produced and the peg-in placeholder is left untouched.
BOOST_AUTO_TEST_CASE(fill_sign_false_is_pure_updater)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    const CKey key = MWEBTestKeys::ToCKey(TestSecret('7'));

    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    ImportDescriptor(m_wallet, strprintf("wpkh(%s)", EncodeSecret(key)));

    PartiallySignedTransaction psbt = MixedPeginPSBT(key, keys.Address(0));

    bool complete = true;
    BOOST_REQUIRE_EQUAL(TransactionError::OK,
                        m_wallet.FillPSBT(psbt, complete, SIGHASH_ALL, /*sign=*/false, /*bip32derivs=*/false, nullptr, /*finalize=*/true));

    BOOST_CHECK(!complete);
    BOOST_CHECK(psbt.inputs[0].partial_sigs.empty());
    BOOST_CHECK(psbt.inputs[0].final_script_witness.IsNull());
    BOOST_CHECK(!psbt.outputs[1].mweb_sig.has_value());
    BOOST_CHECK(!psbt.kernels[0].sig.has_value());
    BOOST_CHECK(!psbt.mweb_tx_offset.has_value());

    // The peg-in script is still the placeholder: no rewrite without signing.
    mw::Hash script_kernel_id;
    BOOST_REQUIRE(psbt.outputs[0].script.has_value());
    BOOST_REQUIRE(psbt.outputs[0].script->IsMWEBPegin(&script_kernel_id));
    BOOST_CHECK(script_kernel_id.IsZero());
}

BOOST_AUTO_TEST_CASE(fill_sighash_types)
{
    const CKey key = MWEBTestKeys::ToCKey(TestSecret('7'));
    const CScript wpkh_script = GetScriptForDestination(WitnessV0KeyHash(key.GetPubKey()));

    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    ImportDescriptor(m_wallet, strprintf("wpkh(%s)", EncodeSecret(key)));

    PartiallySignedTransaction psbt;
    psbt.m_psbt_version = 2;
    psbt.tx_version = 2;
    PSBTInput input(2);
    input.prev_txid = uint256::ONE;
    input.prev_out = 0;
    input.witness_utxo = CTxOut(110'000, wpkh_script);
    psbt.inputs.push_back(input);
    PSBTOutput output(2);
    output.amount = 100'000;
    output.script = wpkh_script;
    psbt.outputs.push_back(output);

    const int sighash = SIGHASH_SINGLE | SIGHASH_ANYONECANPAY;
    bool complete = false;
    BOOST_REQUIRE_EQUAL(TransactionError::OK,
                        m_wallet.FillPSBT(psbt, complete, sighash, /*sign=*/true, /*bip32derivs=*/false, nullptr, /*finalize=*/true));
    BOOST_CHECK(complete);

    // The produced signature's trailing hashtype byte reflects the request.
    BOOST_REQUIRE(!psbt.inputs[0].final_script_witness.IsNull());
    const std::vector<unsigned char>& sig = psbt.inputs[0].final_script_witness.stack.at(0);
    BOOST_REQUIRE(!sig.empty());
    BOOST_CHECK_EQUAL(sig.back(), static_cast<unsigned char>(sighash));
}

BOOST_AUTO_TEST_CASE(fill_error_paths)
{
    // An MWEB descriptor inconsistent with the input's output pubkey is an
    // invalid PSBT; nothing is signed.
    {
        const MWEBTestKeys keys = MWEBTestKeys::Create();
        const SecretKey shared_secret = TestSecret('b');
        PartiallySignedTransaction psbt = SignableMWEBPSBT(mw::Hash::ValueOf(1), shared_secret, keys.Address(0));
        psbt.inputs[0].mweb_address_descriptor = keys.Descriptor(0);
        psbt.inputs[0].mweb_output_pubkey = keys.OutputPubKey(5, shared_secret); // wrong subaddress

        LOCK(m_wallet.cs_wallet);
        bool complete = true;
        size_t n_signed = 0;
        BOOST_CHECK(m_wallet.FillPSBT(psbt, complete, SIGHASH_ALL, /*sign=*/true, /*bip32derivs=*/false, &n_signed, /*finalize=*/true) == TransactionError::INVALID_PSBT);
        BOOST_CHECK_EQUAL(n_signed, 0U);
        BOOST_CHECK(!psbt.inputs[0].mweb_sig.has_value());
    }

    // A canonical input whose previous transaction is unknown to the wallet
    // simply stays unsigned: not an error, just incomplete.
    {
        PartiallySignedTransaction psbt;
        psbt.m_psbt_version = 2;
        psbt.tx_version = 2;
        PSBTInput input(2);
        input.prev_txid = uint256::ONE;
        input.prev_out = 0;
        psbt.inputs.push_back(input);

        LOCK(m_wallet.cs_wallet);
        bool complete = true;
        BOOST_REQUIRE_EQUAL(TransactionError::OK,
                            m_wallet.FillPSBT(psbt, complete, SIGHASH_ALL, /*sign=*/true, /*bip32derivs=*/false, nullptr, /*finalize=*/true));
        BOOST_CHECK(!complete);
        BOOST_CHECK(!PSBTInputSigned(psbt.inputs[0]));
    }
}

//! The signing-key sources must yield usable values even for a wallet without
//! an MWEB keychain (the documented random fallback), so descriptor-key
//! signing works on key-less wallets.
BOOST_AUTO_TEST_CASE(rewind_and_sender_key_sources)
{
    const SecretKey rewind = GetMWEBRewindKeyForSigning(m_wallet);
    BOOST_CHECK_EQUAL(rewind.size(), 32U);

    const mw::SenderKeyGenerator generate = GetMWEBSenderKeyGeneratorForSigning(m_wallet);
    const util::Result<SecretKey> sender_key = generate();
    BOOST_REQUIRE(bool{sender_key});
    BOOST_CHECK_EQUAL(sender_key->size(), 32U);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
