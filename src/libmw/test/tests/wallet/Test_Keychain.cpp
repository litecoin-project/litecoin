// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/crypto/Blinds.h>
#include <mw/crypto/Bulletproofs.h>
#include <mw/crypto/Hasher.h>
#include <mw/crypto/Schnorr.h>
#include <mw/crypto/SecretKeys.h>
#include <mw/models/tx/Output.h>
#include <mw/models/wallet/StealthAddress.h>
#include <mw/wallet/Keychain.h>

#include <crypto/common.h>
#include <test_framework/Deserializer.h>
#include <test_framework/TestMWEB.h>

BOOST_FIXTURE_TEST_SUITE(TestKeychain, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(SenderKeys)
{
    const SecretKey scan_secret = SecretKey::FromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    mw::Keychain keychain(nullptr, scan_secret, PublicKey::Random());

    const SecretKey sender_key_0 = keychain.GetSenderKey(0);
    BOOST_CHECK(sender_key_0 == keychain.GetSenderKey(0));
    BOOST_CHECK(sender_key_0 != keychain.GetSenderKey(1));
    BOOST_CHECK(PublicKey::From(sender_key_0) == PublicKey::From(keychain.GetSenderKey(0)));

    mw::Keychain other_keychain(nullptr, SecretKey::Random(), PublicKey::Random());
    BOOST_CHECK(sender_key_0 != other_keychain.GetSenderKey(0));
}

BOOST_AUTO_TEST_CASE(Create)
{
    // Generate receiver master keys
    SecretKey a = SecretKey::Random();
    SecretKey b = SecretKey::Random();

    PublicKey A = PublicKey::From(a);

    // Generate receiver sub-address (i = 10)
    SecretKey b_i = SecretKeys::From(b)
        .Add(Hasher().Append(A).Append(10).Append(a).hash())
        .Total();
    StealthAddress receiver_subaddr(
        PublicKey::From(b_i).Mul(a),
        PublicKey::From(b_i)
    );

    // Build output
    uint64_t amount = 1'234'567;
    BlindingFactor blind;
    SecretKey sender_key = SecretKey::Random();
    mw::Output output = mw::Output::Create(
        &blind,
        sender_key,
        SecretKey::Random(),
        receiver_subaddr,
        amount
    );
    Commitment expected_commit = Commitment::Switch(blind, amount);

    // Verify bulletproof
    ProofData proof_data = output.BuildProofData();
    BOOST_REQUIRE(proof_data.commitment == expected_commit);
    BOOST_REQUIRE(proof_data.pRangeProof == output.GetRangeProof());
    BOOST_REQUIRE(Bulletproofs::BatchVerify({ output.BuildProofData() }));

    // Verify sender signature
    SignedMessage signed_msg = output.BuildSignedMsg();
    BOOST_REQUIRE(signed_msg.GetPublicKey() == PublicKey::From(sender_key));
    BOOST_REQUIRE(Schnorr::BatchVerify({ signed_msg }));

    // Verify Output ID
    mw::Hash expected_id = Hasher()
        .Append(output.GetCommitment())
        .Append(output.GetSenderPubKey())
        .Append(output.GetReceiverPubKey())
        .Append(output.GetOutputMessage().GetHash())
        .Append(output.GetRangeProof()->GetHash())
        .Append(output.GetSignature())
        .hash();
    BOOST_REQUIRE(output.GetOutputID() == expected_id);

    // Getters
    BOOST_REQUIRE(output.GetCommitment() == expected_commit);

    // MW: TODO - This is what we used for figuring out the keychain, but now we need actual tests that use it
    // Include tests with:
    // 1. Spend private key
    // 2. Spend pubkey only
    // 3. No spend key

    //
    // Test Restoring Output
    //
    {
        // Check view tag
        BOOST_REQUIRE(Hashed(EHashTag::TAG, output.Ke().Mul(a))[0] == output.GetViewTag());

        // Make sure B belongs to wallet
        SecretKey t = Hashed(EHashTag::DERIVE, output.Ke().Mul(a));
        BOOST_REQUIRE(receiver_subaddr.B() == output.Ko().Div(Hashed(EHashTag::OUT_KEY, t)));

        SecretKey r = Hashed(EHashTag::BLIND, t);
        const mw::Hash value_mask_hash = Hashed(EHashTag::VALUE_MASK, t);
        uint64_t value = output.GetMaskedValue() ^ ReadLE64(value_mask_hash.data());
        BigInt<16> n = output.GetMaskedNonce() ^ BigInt<16>(Hashed(EHashTag::NONCE_MASK, t).data());

        BOOST_REQUIRE(Commitment::Switch(r, value) == output.GetCommitment());

        // Calculate Carol's sending key 's' and check that s*B ?= Ke
        SecretKey s = Hasher(EHashTag::SEND_KEY)
            .Append(receiver_subaddr.A())
            .Append(receiver_subaddr.B())
            .Append(value)
            .Append(n)
            .hash();
        BOOST_REQUIRE(output.Ke() == receiver_subaddr.B().Mul(s));

        // Make sure receiver can generate the spend key
        SecretKey spend_key = SecretKeys::From(b_i)
            .Mul(Hashed(EHashTag::OUT_KEY, t))
            .Total();
        BOOST_REQUIRE(output.GetReceiverPubKey() == PublicKey::From(spend_key));
    }
}

BOOST_AUTO_TEST_SUITE_END()
