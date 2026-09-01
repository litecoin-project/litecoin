// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <mw/crypto/KeyDerivation.h>
#include <psbt.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <streams.h>
#include <test/util/psbt.h>
#include <wallet/mweb_psbt.h>
#include <wallet/test/psbt_test_utils.h>

#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>

namespace wallet {

using test::MockMWEBKeyStore;
using test::MWEBTestKeys;
using test::TestSecret;

BOOST_FIXTURE_TEST_SUITE(mweb_psbt_tests, BasicTestingSetup)

using test::PeginTx;
using test::SignableMWEBPSBT;
using test::TestSenderKeyGenerator;
using psbt_test::MWEBInput;

// ---------------------------------------------------------------------------
// Stage A: ResolveMWEBInputKeys
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(shared_secret_ecdh_symmetric)
{
    const SecretKey a = TestSecret('1');
    const SecretKey e = TestSecret('2');

    BOOST_CHECK(mw::RecoverSharedSecret(PublicKey::From(e), a) == mw::RecoverSharedSecret(PublicKey::From(a), e));
    BOOST_CHECK(!(mw::RecoverSharedSecret(PublicKey::From(e), a) == mw::RecoverSharedSecret(PublicKey::From(e), e)));
}

BOOST_AUTO_TEST_CASE(resolve_from_descriptor_private_keys)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    const uint32_t index{3};
    const SecretKey shared_secret = TestSecret('c');

    PSBTInput input = MWEBInput(mw::Hash::ValueOf(1));
    input.mweb_address_descriptor = keys.Descriptor(index);
    input.mweb_shared_secret = shared_secret;
    input.mweb_output_pubkey = keys.OutputPubKey(index, shared_secret);

    const MockMWEBKeyStore keystore; // empty: everything must come from the descriptor
    util::Result<std::optional<SecretKey>> result = ResolveMWEBInputKeys(input, keystore);
    BOOST_REQUIRE(bool{result});
    BOOST_REQUIRE(result->has_value());

    // The invariant mw::SignInput relies on: the spend key must match the output pubkey.
    BOOST_CHECK(PublicKey::From(**result) == *input.mweb_output_pubkey);
    BOOST_CHECK(**result == mw::DeriveOutputSpendKey(keys.SubaddressSpendSecret(index), shared_secret));
}

BOOST_AUTO_TEST_CASE(resolve_infers_descriptor_from_coin)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    const uint32_t index{0};
    const mw::Hash output_id = mw::Hash::ValueOf(2);
    const SecretKey shared_secret = TestSecret('d');

    MockMWEBKeyStore keystore;
    mw::WalletCoin coin;
    coin.output_id = output_id;
    coin.shared_secret = shared_secret;
    keystore.m_coins[output_id] = coin;
    keystore.m_inferred_descriptor = keys.Descriptor(index);

    PSBTInput input = MWEBInput(output_id);
    input.mweb_output_pubkey = keys.OutputPubKey(index, shared_secret);

    util::Result<std::optional<SecretKey>> result = ResolveMWEBInputKeys(input, keystore);
    BOOST_REQUIRE(bool{result});

    // Descriptor inferred from the coin, shared secret taken from the coin,
    // spend key derived from the descriptor's private keys.
    BOOST_CHECK(input.mweb_address_descriptor == keystore.m_inferred_descriptor);
    BOOST_REQUIRE(input.mweb_shared_secret.has_value());
    BOOST_CHECK(*input.mweb_shared_secret == shared_secret);
    BOOST_REQUIRE(result->has_value());
    BOOST_CHECK(PublicKey::From(**result) == *input.mweb_output_pubkey);
}

BOOST_AUTO_TEST_CASE(resolve_derives_shared_secret_from_key_exchange_pubkey)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    const uint32_t index{1};
    const SecretKey ephemeral = TestSecret('e');
    const PublicKey key_exchange_pubkey = PublicKey::From(ephemeral);
    const SecretKey expected_secret = mw::RecoverSharedSecret(key_exchange_pubkey, keys.scan_secret);

    PSBTInput input = MWEBInput(mw::Hash::ValueOf(3));
    input.mweb_address_descriptor = keys.Descriptor(index);
    input.mweb_key_exchange_pubkey = key_exchange_pubkey;
    input.mweb_output_pubkey = keys.OutputPubKey(index, expected_secret);

    const MockMWEBKeyStore keystore;
    util::Result<std::optional<SecretKey>> result = ResolveMWEBInputKeys(input, keystore);
    BOOST_REQUIRE(bool{result});
    BOOST_REQUIRE(input.mweb_shared_secret.has_value());
    BOOST_CHECK(*input.mweb_shared_secret == expected_secret);
    BOOST_REQUIRE(result->has_value());
    BOOST_CHECK(PublicKey::From(**result) == *input.mweb_output_pubkey);
}

BOOST_AUTO_TEST_CASE(resolve_scan_only_keychain_exports_shared_secret)
{
    const SecretKey scan_secret = TestSecret('4');
    const SecretKey ephemeral = TestSecret('5');
    const PublicKey key_exchange_pubkey = PublicKey::From(ephemeral);
    const SecretKey expected_secret = mw::RecoverSharedSecret(key_exchange_pubkey, scan_secret);
    const mw::Hash output_id = mw::Hash::ValueOf(9);

    MockMWEBKeyStore keystore;
    keystore.m_active_keychain = std::make_shared<mw::Keychain>(
        nullptr,
        scan_secret,
        std::optional<PublicKey>{}
    );
    mw::WalletCoin coin;
    coin.output_id = output_id;
    coin.address_index = 2;
    keystore.m_coins[output_id] = coin;

    PSBTInput input = MWEBInput(output_id);
    input.mweb_key_exchange_pubkey = key_exchange_pubkey;
    util::Result<std::optional<SecretKey>> result = ResolveMWEBInputKeys(input, keystore);

    BOOST_REQUIRE(bool{result});
    BOOST_CHECK(!result->has_value());
    BOOST_REQUIRE(input.mweb_shared_secret);
    BOOST_CHECK(*input.mweb_shared_secret == expected_secret);
}

BOOST_AUTO_TEST_CASE(resolve_descriptor_precedes_legacy_active_keychain)
{
    const MWEBTestKeys descriptor_keys = MWEBTestKeys::Create('6', '7');
    const SecretKey active_scan_secret = TestSecret('8');
    const SecretKey ephemeral = TestSecret('9');
    const PublicKey key_exchange_pubkey = PublicKey::From(ephemeral);
    const SecretKey expected_secret = mw::RecoverSharedSecret(key_exchange_pubkey, descriptor_keys.scan_secret);
    const mw::Hash output_id = mw::Hash::ValueOf(10);

    MockMWEBKeyStore keystore;
    keystore.m_active_keychain = std::make_shared<mw::Keychain>(
        nullptr,
        active_scan_secret,
        std::optional<PublicKey>{}
    );
    mw::WalletCoin coin;
    coin.output_id = output_id;
    keystore.m_coins[output_id] = coin;

    PSBTInput input = MWEBInput(output_id);
    input.mweb_address_descriptor = descriptor_keys.Descriptor(4);
    input.mweb_key_exchange_pubkey = key_exchange_pubkey;
    input.mweb_output_pubkey = descriptor_keys.OutputPubKey(4, expected_secret);

    util::Result<std::optional<SecretKey>> result = ResolveMWEBInputKeys(input, keystore);
    BOOST_REQUIRE(bool{result});
    BOOST_REQUIRE(result->has_value());
    BOOST_REQUIRE(input.mweb_shared_secret);
    BOOST_CHECK(*input.mweb_shared_secret == expected_secret);
    BOOST_CHECK(PublicKey::From(**result) == *input.mweb_output_pubkey);
}

BOOST_AUTO_TEST_CASE(resolve_descriptor_mismatch_is_error)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    const SecretKey shared_secret = TestSecret('c');

    PSBTInput input = MWEBInput(mw::Hash::ValueOf(4));
    input.mweb_address_descriptor = keys.Descriptor(0);
    input.mweb_shared_secret = shared_secret;
    // Output pubkey belongs to a different address (index 5, not 0).
    input.mweb_output_pubkey = keys.OutputPubKey(5, shared_secret);

    const MockMWEBKeyStore keystore;
    util::Result<std::optional<SecretKey>> result = ResolveMWEBInputKeys(input, keystore);
    BOOST_REQUIRE(!result);
    BOOST_CHECK(util::ErrorString(result).original.find("does not match") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(resolve_invalid_descriptor_is_error)
{
    PSBTInput input = MWEBInput(mw::Hash::ValueOf(5));
    input.mweb_address_descriptor = "definitely-not-a-descriptor";

    const MockMWEBKeyStore keystore;
    BOOST_CHECK(!ResolveMWEBInputKeys(input, keystore));

    input.mweb_address_descriptor = "wpkh(xprv9s21ZrQH143K2LE7W4Xf3jATf9jECxSb7wj91ZnmY4qEJrS66Qru9RFqq8xbkgT32ya6HqYJweFdJUEDf5Q6JFV7jMiUws7kQfe6Tv4RbfN/0h/0h/0h)";
    util::Result<std::optional<SecretKey>> result = ResolveMWEBInputKeys(input, keystore);
    BOOST_REQUIRE(!result);
    BOOST_CHECK(util::ErrorString(result).original.find("wrong output type") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(resolve_is_noop_when_data_absent)
{
    PSBTInput input = MWEBInput(mw::Hash::ValueOf(6));

    const MockMWEBKeyStore keystore;
    util::Result<std::optional<SecretKey>> result = ResolveMWEBInputKeys(input, keystore);

    // Not knowing the input is not an error — another signer may hold the keys.
    BOOST_REQUIRE(bool{result});
    BOOST_CHECK(!result->has_value());
    BOOST_CHECK(!input.mweb_address_descriptor.has_value());
    BOOST_CHECK(!input.mweb_shared_secret.has_value());
}

BOOST_AUTO_TEST_CASE(resolve_preserves_existing_shared_secret)
{
    const mw::Hash output_id = mw::Hash::ValueOf(8);
    const SecretKey input_secret = TestSecret('a');
    const SecretKey coin_secret = TestSecret('b');

    MockMWEBKeyStore keystore;
    mw::WalletCoin coin;
    coin.output_id = output_id;
    coin.shared_secret = coin_secret;
    keystore.m_coins[output_id] = coin;

    PSBTInput input = MWEBInput(output_id);
    input.mweb_shared_secret = input_secret;

    BOOST_REQUIRE(bool{ResolveMWEBInputKeys(input, keystore)});

    // The input's own field takes precedence over wallet state.
    BOOST_REQUIRE(input.mweb_shared_secret.has_value());
    BOOST_CHECK(*input.mweb_shared_secret == input_secret);
}

// ---------------------------------------------------------------------------
// Stage B: SignPSBTMWEBComponents
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(sign_mweb_end_to_end)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    const mw::Hash output_id = mw::Hash::ValueOf(1);
    const SecretKey spend_key = TestSecret('a');
    const SecretKey shared_secret = TestSecret('b');

    PartiallySignedTransaction psbt = SignableMWEBPSBT(output_id, shared_secret, keys.Address(0));
    psbt.m_tx_modifiable = std::bitset<8>{0x03};

    const std::unordered_map<mw::Hash, SecretKey> spend_keys{{output_id, spend_key}};
    util::Result<MWEBSignOutcome> outcome = SignPSBTMWEBComponents(psbt, spend_keys, TestSecret('c'), TestSenderKeyGenerator());
    BOOST_REQUIRE(bool{outcome});

    // Input signed and verifiable
    BOOST_REQUIRE(psbt.inputs[0].mweb_sig.has_value());
    BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 0, nullptr));

    // Output finalized
    BOOST_CHECK(psbt.outputs[0].mweb_commit.has_value());
    BOOST_CHECK(psbt.outputs[0].mweb_rangeproof.has_value());
    BOOST_CHECK(psbt.outputs[0].mweb_sig.has_value());

    // Kernel finalized, fee preserved
    BOOST_CHECK(psbt.kernels[0].commit.has_value());
    BOOST_CHECK(psbt.kernels[0].sig.has_value());
    BOOST_CHECK(psbt.kernels[0].fee == std::optional<CAmount>{10'000});

    // Global offsets set, modifiable flags cleared
    BOOST_CHECK(psbt.mweb_tx_offset.has_value());
    BOOST_CHECK(psbt.mweb_stealth_offset.has_value());
    BOOST_REQUIRE(psbt.m_tx_modifiable.has_value());
    BOOST_CHECK(psbt.m_tx_modifiable->none());

    // Discovered wallet coin for the new output
    BOOST_REQUIRE_EQUAL(outcome->discovered_coins.size(), 1U);
    BOOST_CHECK(outcome->discovered_coins.begin()->second.address == keys.Address(0));

    BOOST_CHECK(psbt.IsComplete());
}

BOOST_AUTO_TEST_CASE(sign_mweb_missing_spend_key_is_error)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    PartiallySignedTransaction psbt = SignableMWEBPSBT(mw::Hash::ValueOf(1), TestSecret('b'), keys.Address(0));

    util::Result<MWEBSignOutcome> outcome = SignPSBTMWEBComponents(psbt, /*spend_keys=*/{}, TestSecret('c'), TestSenderKeyGenerator());
    BOOST_REQUIRE(!outcome);
    BOOST_CHECK(util::ErrorString(outcome).original.find("spend key") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(sign_mweb_already_final_is_noop)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    const mw::Hash output_id = mw::Hash::ValueOf(1);

    PartiallySignedTransaction psbt = SignableMWEBPSBT(output_id, TestSecret('b'), keys.Address(0));
    const std::unordered_map<mw::Hash, SecretKey> spend_keys{{output_id, TestSecret('a')}};
    BOOST_REQUIRE(bool{SignPSBTMWEBComponents(psbt, spend_keys, TestSecret('c'), TestSenderKeyGenerator())});

    CDataStream before(SER_NETWORK, PROTOCOL_VERSION);
    before << psbt;

    // Re-signing a final PSBT must not change it or discover new coins.
    util::Result<MWEBSignOutcome> again = SignPSBTMWEBComponents(psbt, /*spend_keys=*/{}, TestSecret('d'), TestSenderKeyGenerator());
    BOOST_REQUIRE(bool{again});
    BOOST_CHECK(again->discovered_coins.empty());

    CDataStream after(SER_NETWORK, PROTOCOL_VERSION);
    after << psbt;
    BOOST_CHECK(Span{before} == Span{after});
}

BOOST_AUTO_TEST_CASE(sign_mweb_rewrites_pegin_placeholder)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();

    PartiallySignedTransaction psbt(PeginTx(keys.Address(0)), 2);
    BOOST_REQUIRE(bool{SignPSBTMWEBComponents(psbt, /*spend_keys=*/{}, TestSecret('c'), TestSenderKeyGenerator())});

    // The placeholder peg-in script must now commit to the finalized kernel ID.
    BOOST_REQUIRE(psbt.outputs[0].script.has_value());
    mw::Hash script_kernel_id;
    BOOST_REQUIRE(psbt.outputs[0].script->IsMWEBPegin(&script_kernel_id));
    BOOST_CHECK(!script_kernel_id.IsZero());

    const CMutableTransaction signed_tx = psbt.GetUnsignedTx();
    BOOST_REQUIRE(signed_tx.mweb_tx.kernels[0].GetKernelID().has_value());
    BOOST_CHECK(script_kernel_id == *signed_tx.mweb_tx.kernels[0].GetKernelID());
}

BOOST_AUTO_TEST_CASE(sign_mweb_pegin_mismatch_is_error)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();

    // Peg-in output amount differs from the kernel's pegin amount.
    {
        PartiallySignedTransaction psbt(PeginTx(keys.Address(0), /*pegin_vout_amount=*/90'000), 2);
        util::Result<MWEBSignOutcome> outcome = SignPSBTMWEBComponents(psbt, {}, TestSecret('c'), TestSenderKeyGenerator());
        BOOST_REQUIRE(!outcome);
        BOOST_CHECK(util::ErrorString(outcome).original.find("amount does not match") != std::string::npos);
    }

    // Peg-in kernel without a matching canonical peg-in output.
    {
        CMutableTransaction mtx = PeginTx(keys.Address(0));
        mtx.vout.clear();
        PartiallySignedTransaction psbt(mtx, 2);
        util::Result<MWEBSignOutcome> outcome = SignPSBTMWEBComponents(psbt, {}, TestSecret('c'), TestSenderKeyGenerator());
        BOOST_REQUIRE(!outcome);
        BOOST_CHECK(util::ErrorString(outcome).original.find("count does not match") != std::string::npos);
    }
}

//! The ordering lock-in: sighash precomputation data built BEFORE MWEB signing
//! is invalidated by the peg-in script rewrite. Signing against the stale data
//! trips SignatureHash's cache-consistency assertion (and would commit to the
//! wrong outputs hash in a release build). This is why PSBTFiller only builds
//! PrecomputedTransactionData inside the script-signing stage, which cannot
//! run without the MWEB stage's outcome.
BOOST_AUTO_TEST_CASE(pegin_rewrite_invalidates_sighash)
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();

    CKey key;
    key.MakeNewKey(true);
    const CScript wpkh_script = GetScriptForDestination(WitnessV0KeyHash(key.GetPubKey()));

    CMutableTransaction mtx = PeginTx(keys.Address(0));
    mtx.vin.emplace_back(COutPoint(uint256::ONE, 0));

    PartiallySignedTransaction psbt(mtx, 2);
    psbt.inputs[0].witness_utxo = CTxOut(110'000, wpkh_script);

    FlatSigningProvider provider;
    provider.keys.emplace(key.GetPubKey().GetID(), key);
    provider.pubkeys.emplace(key.GetPubKey().GetID(), key.GetPubKey());

    // Precompute sighash data BEFORE the MWEB stage (the bug this guards against).
    const PrecomputedTransactionData stale_txdata = PrecomputePSBTData(psbt);

    BOOST_REQUIRE(bool{SignPSBTMWEBComponents(psbt, /*spend_keys=*/{}, TestSecret('c'), TestSenderKeyGenerator())});

    // The peg-in rewrite changed the transaction's outputs, so the sighash
    // data built before the MWEB stage no longer matches the transaction.
    const PrecomputedTransactionData fresh_txdata = PrecomputePSBTData(psbt);
    BOOST_CHECK(stale_txdata.m_outputs_single_hash != fresh_txdata.m_outputs_single_hash);

    // Signing against data built after the MWEB stage verifies.
    BOOST_CHECK(SignPSBTInput(provider, psbt, 0, &fresh_txdata, SIGHASH_ALL, nullptr, /*finalize=*/true));
    BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 0, &fresh_txdata));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
