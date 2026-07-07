// Copyright (c) 2017-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key_io.h>
#include <mw/crypto/KeyDerivation.h>
#include <mw/models/tx/Input.h>
#include <util/bip32.h>
#include <util/strencodings.h>
#include <wallet/mweb_psbt.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>
#include <wallet/test/psbt_test_utils.h>
#include <wallet/test/wallet_test_fixture.h>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(psbt_wallet_tests, WalletTestingSetup)

static void import_descriptor(CWallet& wallet, const std::string& descriptor)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    FlatSigningProvider provider;
    std::string error;
    std::unique_ptr<Descriptor> desc = Parse(descriptor, provider, error, /* require_checksum=*/ false);
    assert(desc);
    WalletDescriptor w_desc(std::move(desc), 0, 0, 10, 0);
    wallet.AddWalletDescriptor(w_desc, provider, "", false);
}

BOOST_AUTO_TEST_CASE(psbt_updater_test)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);

    // Create prevtxs and add to wallet
    CDataStream s_prev_tx1(ParseHex("0200000000010158e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7501000000171600145f275f436b09a8cc9a2eb2a2f528485c68a56323feffffff02d8231f1b0100000017a914aed962d6654f9a2b36608eb9d64d2b260db4f1118700c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e88702483045022100a22edcc6e5bc511af4cc4ae0de0fcd75c7e04d8c1c3a8aa9d820ed4b967384ec02200642963597b9b1bc22c75e9f3e117284a962188bf5e8a74c895089046a20ad770121035509a48eb623e10aace8bfd0212fdb8a8e5af3c94b0b133b95e114cab89e4f7965000000"), SER_NETWORK, PROTOCOL_VERSION);
    CTransactionRef prev_tx1;
    s_prev_tx1 >> prev_tx1;
    m_wallet.mapWallet.emplace(std::piecewise_construct, std::forward_as_tuple(prev_tx1->GetHash()), std::forward_as_tuple(prev_tx1, TxStateInactive{}, std::nullopt));

    CDataStream s_prev_tx2(ParseHex("0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f618765000000"), SER_NETWORK, PROTOCOL_VERSION);
    CTransactionRef prev_tx2;
    s_prev_tx2 >> prev_tx2;
    m_wallet.mapWallet.emplace(std::piecewise_construct, std::forward_as_tuple(prev_tx2->GetHash()), std::forward_as_tuple(prev_tx2, TxStateInactive{}, std::nullopt));

    // Import descriptors for keys and scripts
    import_descriptor(m_wallet, "sh(multi(2,xprv9s21ZrQH143K2LE7W4Xf3jATf9jECxSb7wj91ZnmY4qEJrS66Qru9RFqq8xbkgT32ya6HqYJweFdJUEDf5Q6JFV7jMiUws7kQfe6Tv4RbfN/0h/0h/0h,xprv9s21ZrQH143K2LE7W4Xf3jATf9jECxSb7wj91ZnmY4qEJrS66Qru9RFqq8xbkgT32ya6HqYJweFdJUEDf5Q6JFV7jMiUws7kQfe6Tv4RbfN/0h/0h/1h))");
    import_descriptor(m_wallet, "sh(wsh(multi(2,xprv9s21ZrQH143K2LE7W4Xf3jATf9jECxSb7wj91ZnmY4qEJrS66Qru9RFqq8xbkgT32ya6HqYJweFdJUEDf5Q6JFV7jMiUws7kQfe6Tv4RbfN/0h/0h/2h,xprv9s21ZrQH143K2LE7W4Xf3jATf9jECxSb7wj91ZnmY4qEJrS66Qru9RFqq8xbkgT32ya6HqYJweFdJUEDf5Q6JFV7jMiUws7kQfe6Tv4RbfN/0h/0h/3h)))");
    import_descriptor(m_wallet, "wpkh(xprv9s21ZrQH143K2LE7W4Xf3jATf9jECxSb7wj91ZnmY4qEJrS66Qru9RFqq8xbkgT32ya6HqYJweFdJUEDf5Q6JFV7jMiUws7kQfe6Tv4RbfN/0h/0h/*h)");

    // Call FillPSBT
    PartiallySignedTransaction psbtx;
    CDataStream ssData(ParseHex("70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000000000000000000"), SER_NETWORK, PROTOCOL_VERSION);
    ssData >> psbtx;

    // Fill transaction with our data
    bool complete = true;
    BOOST_REQUIRE_EQUAL(TransactionError::OK, m_wallet.FillPSBT(psbtx, complete, SIGHASH_ALL, false, true));

    // Get the final tx
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << psbtx;
    std::string final_hex = HexStr(ssTx);
    BOOST_CHECK_EQUAL(final_hex, "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f6187650000000104475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae2206029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f10d90c6a4f000000800000008000000080220602dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d710d90c6a4f0000008000000080010000800001008a020000000158e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7501000000171600145f275f436b09a8cc9a2eb2a2f528485c68a56323feffffff02d8231f1b0100000017a914aed962d6654f9a2b36608eb9d64d2b260db4f1118700c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e8876500000001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e88701042200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903010547522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae2206023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7310d90c6a4f000000800000008003000080220603089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc10d90c6a4f00000080000000800200008000220203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca5877110d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000");

    // Mutate the transaction so that one of the inputs is invalid
    psbtx.tx->vin[0].prevout.n = 2;
    psbtx.inputs[0].prev_out = 2;

    // Try to sign the mutated input
    SignatureData sigdata;
    BOOST_CHECK(m_wallet.FillPSBT(psbtx, complete, SIGHASH_ALL, true, true) != TransactionError::OK);
}

BOOST_AUTO_TEST_CASE(psbt_mweb_signature_verification_test)
{
    const mw::Input mweb_input = mw::Input::Create(
        mw::Hash::ValueOf(1),
        Commitment::Transparent(1),
        SecretKey::FromHex(std::string(64, '1')),
        SecretKey::FromHex(std::string(64, '2'))
    );

    PartiallySignedTransaction psbt(CMutableTransaction{}, 2);
    PSBTInput psbt_input(2);
    psbt_input.mweb_output_id = mweb_input.GetOutputID();
    psbt_input.mweb_output_commit = mweb_input.GetCommitment();
    psbt_input.mweb_output_pubkey = mweb_input.GetOutputPubKey();
    psbt_input.mweb_input_pubkey = mweb_input.GetInputPubKey();
    psbt_input.mweb_features = mweb_input.GetFeatures();
    psbt_input.mweb_sig = mweb_input.GetSignature();
    psbt.inputs.push_back(psbt_input);

    BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 0, nullptr));

    Signature tampered_sig = mweb_input.GetSignature();
    tampered_sig.data()[0] ^= 0x01;
    psbt.inputs[0].mweb_sig = tampered_sig;
    BOOST_CHECK(!PSBTInputSignedAndVerified(psbt, 0, nullptr));

    psbt.inputs[0].mweb_sig = mweb_input.GetSignature();
    psbt.inputs[0].mweb_input_pubkey = std::nullopt;
    BOOST_CHECK(!PSBTInputSignedAndVerified(psbt, 0, nullptr));
}

//! FillPSBT with sign=false must act as an Updater for MWEB inputs (derive and
//! attach the shared secret) without producing signatures. The external-signer
//! flow depends on this split: it runs a sign=false pass before the signing pass.
BOOST_AUTO_TEST_CASE(fill_psbt_sign_false_fills_mweb_metadata)
{
    const test::MWEBTestKeys keys = test::MWEBTestKeys::Create();
    const SecretKey ephemeral = test::TestSecret('e');
    const PublicKey key_exchange_pubkey = PublicKey::From(ephemeral);
    const SecretKey expected_secret = mw::RecoverSharedSecret(key_exchange_pubkey, keys.scan_secret);

    PartiallySignedTransaction psbt(CMutableTransaction{}, 2);
    PSBTInput input(2);
    input.mweb_output_id = mw::Hash::ValueOf(1);
    input.mweb_address_descriptor = keys.Descriptor(0);
    input.mweb_key_exchange_pubkey = key_exchange_pubkey;
    input.mweb_output_pubkey = keys.OutputPubKey(0, expected_secret);
    psbt.inputs.push_back(input);

    LOCK(m_wallet.cs_wallet);
    bool complete = true;
    BOOST_REQUIRE_EQUAL(TransactionError::OK, m_wallet.FillPSBT(psbt, complete, SIGHASH_ALL, /*sign=*/false, /*bip32derivs=*/true));

    // Updater metadata was attached...
    BOOST_REQUIRE(psbt.inputs[0].mweb_shared_secret.has_value());
    BOOST_CHECK(*psbt.inputs[0].mweb_shared_secret == expected_secret);

    // ...but no signature was produced.
    BOOST_CHECK(!psbt.inputs[0].mweb_sig.has_value());
    BOOST_CHECK(!complete);
}

BOOST_AUTO_TEST_CASE(fill_psbt_invalid_mweb_descriptor_is_invalid_psbt)
{
    PartiallySignedTransaction psbt(CMutableTransaction{}, 2);
    PSBTInput input(2);
    input.mweb_output_id = mw::Hash::ValueOf(1);
    input.mweb_address_descriptor = "definitely-not-a-descriptor";
    psbt.inputs.push_back(input);

    LOCK(m_wallet.cs_wallet);
    bool complete = true;
    BOOST_CHECK(m_wallet.FillPSBT(psbt, complete, SIGHASH_ALL, /*sign=*/false, /*bip32derivs=*/true) == TransactionError::INVALID_PSBT);
}

BOOST_AUTO_TEST_CASE(parse_hd_keypath)
{
    HDKeyPath keypath;

    BOOST_CHECK(ParseHDKeypath("1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1", keypath));
    BOOST_CHECK(!ParseHDKeypath("///////////////////////////", keypath));

    BOOST_CHECK(ParseHDKeypath("1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1'/1", keypath));
    BOOST_CHECK(!ParseHDKeypath("//////////////////////////'/", keypath));

    BOOST_CHECK(ParseHDKeypath("1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/", keypath));
    BOOST_CHECK(!ParseHDKeypath("1///////////////////////////", keypath));

    BOOST_CHECK(ParseHDKeypath("1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1'/", keypath));
    BOOST_CHECK(!ParseHDKeypath("1/'//////////////////////////", keypath));

    BOOST_CHECK(ParseHDKeypath("", keypath));
    BOOST_CHECK(!ParseHDKeypath(" ", keypath));

    BOOST_CHECK(ParseHDKeypath("0", keypath));
    BOOST_CHECK(!ParseHDKeypath("O", keypath));

    BOOST_CHECK(ParseHDKeypath("0000'/0000'/0000'", keypath));
    BOOST_CHECK(!ParseHDKeypath("0000,/0000,/0000,", keypath));

    BOOST_CHECK(ParseHDKeypath("01234", keypath));
    BOOST_CHECK(!ParseHDKeypath("0x1234", keypath));

    BOOST_CHECK(ParseHDKeypath("1", keypath));
    BOOST_CHECK(!ParseHDKeypath(" 1", keypath));

    BOOST_CHECK(ParseHDKeypath("42", keypath));
    BOOST_CHECK(!ParseHDKeypath("m42", keypath));

    BOOST_CHECK(ParseHDKeypath("4294967295", keypath)); // 4294967295 == 0xFFFFFFFF (uint32_t max)
    BOOST_CHECK(!ParseHDKeypath("4294967296", keypath)); // 4294967296 == 0xFFFFFFFF (uint32_t max) + 1

    BOOST_CHECK(ParseHDKeypath("m", keypath));
    BOOST_CHECK(!ParseHDKeypath("n", keypath));

    BOOST_CHECK(ParseHDKeypath("m/", keypath));
    BOOST_CHECK(!ParseHDKeypath("n/", keypath));

    BOOST_CHECK(ParseHDKeypath("m/0", keypath));
    BOOST_CHECK(!ParseHDKeypath("n/0", keypath));

    BOOST_CHECK(ParseHDKeypath("m/0'", keypath));
    BOOST_CHECK(!ParseHDKeypath("m/0''", keypath));

    BOOST_CHECK(ParseHDKeypath("m/0'/0'", keypath));
    BOOST_CHECK(!ParseHDKeypath("m/'0/0'", keypath));

    BOOST_CHECK(ParseHDKeypath("m/0/0", keypath));
    BOOST_CHECK(!ParseHDKeypath("n/0/0", keypath));

    BOOST_CHECK(ParseHDKeypath("m/0/0/00", keypath));
    BOOST_CHECK(!ParseHDKeypath("m/0/0/f00", keypath));

    BOOST_CHECK(ParseHDKeypath("m/0/0/000000000000000000000000000000000000000000000000000000000000000000000000000000000000", keypath));
    BOOST_CHECK(!ParseHDKeypath("m/1/1/111111111111111111111111111111111111111111111111111111111111111111111111111111111111", keypath));

    BOOST_CHECK(ParseHDKeypath("m/0/00/0", keypath));
    BOOST_CHECK(!ParseHDKeypath("m/0'/00/'0", keypath));

    BOOST_CHECK(ParseHDKeypath("m/1/", keypath));
    BOOST_CHECK(!ParseHDKeypath("m/1//", keypath));

    BOOST_CHECK(ParseHDKeypath("m/0/4294967295", keypath)); // 4294967295 == 0xFFFFFFFF (uint32_t max)
    BOOST_CHECK(!ParseHDKeypath("m/0/4294967296", keypath)); // 4294967296 == 0xFFFFFFFF (uint32_t max) + 1

    BOOST_CHECK(ParseHDKeypath("m/4294967295", keypath)); // 4294967295 == 0xFFFFFFFF (uint32_t max)
    BOOST_CHECK(!ParseHDKeypath("m/4294967296", keypath)); // 4294967296 == 0xFFFFFFFF (uint32_t max) + 1

    {
        HDKeyPath mweb_keypath;
        BOOST_REQUIRE(ParseHDKeypath("x/0", mweb_keypath));
        BOOST_CHECK(mweb_keypath.path.empty());
        BOOST_REQUIRE(mweb_keypath.mweb_index.has_value());
        BOOST_CHECK_EQUAL(*mweb_keypath.mweb_index, 0U);
        BOOST_CHECK_EQUAL(FormatHDKeypath(mweb_keypath), "");
        BOOST_CHECK_EQUAL(WriteHDKeypath(mweb_keypath), "x/0");
    }

    {
        HDKeyPath mweb_keypath;
        BOOST_REQUIRE(ParseHDKeypath("x/4294967295", mweb_keypath)); // 4294967295 == 0xFFFFFFFF (uint32_t max)
        BOOST_CHECK(mweb_keypath.path.empty());
        BOOST_REQUIRE(mweb_keypath.mweb_index.has_value());
        BOOST_CHECK_EQUAL(*mweb_keypath.mweb_index, 4294967295U);
        BOOST_CHECK_EQUAL(FormatHDKeypath(mweb_keypath), "");
        BOOST_CHECK_EQUAL(WriteHDKeypath(mweb_keypath), "x/4294967295");
    }

    {
        HDKeyPath mixed_keypath;
        mixed_keypath.path = {0x80000000};
        mixed_keypath.mweb_index = 42;
        BOOST_CHECK_EQUAL(FormatHDKeypath(mixed_keypath), "/0'");
        BOOST_CHECK_EQUAL(WriteHDKeypath(mixed_keypath), "m/0'");
    }

    BOOST_CHECK(!ParseHDKeypath("x", keypath));
    BOOST_CHECK(!ParseHDKeypath("x/", keypath));
    BOOST_CHECK(!ParseHDKeypath("m/0/x", keypath));
    BOOST_CHECK(!ParseHDKeypath("m/0/x/", keypath));
    BOOST_CHECK(!ParseHDKeypath("m/0'/100'/1'/x/42", keypath));
    BOOST_CHECK(!ParseHDKeypath("x/0'", keypath));
    BOOST_CHECK(!ParseHDKeypath("x/0/1", keypath));
    BOOST_CHECK(!ParseHDKeypath("x/x/0", keypath));
    BOOST_CHECK(!ParseHDKeypath("x/4294967296", keypath)); // 4294967296 == 0xFFFFFFFF (uint32_t max) + 1
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
