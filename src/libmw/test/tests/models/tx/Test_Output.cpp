#include <catch.hpp>

#include <mw/crypto/Schnorr.h>
#include <mw/crypto/Bulletproofs.h>
#include <mw/crypto/Random.h>
#include <mw/models/tx/Output.h>
#include <mw/models/wallet/StealthAddress.h>

TEST_CASE("Output::Create")
{
    // Generate receiver addr
    SecretKey a = Random::CSPRNG<32>();
    SecretKey b = Random::CSPRNG<32>();
    StealthAddress receiver_addr = StealthAddress(
        PublicKey::From(a).Mul(b),
        PublicKey::From(b)
    );

    // Build output
    EOutputFeatures features = EOutputFeatures::DEFAULT_OUTPUT;
    uint64_t amount = 1'234'567;
    BlindingFactor blind;
    SecretKey sender_key = Random::CSPRNG<32>();
    Output output = Output::Create(
        blind,
        features,
        sender_key,
        receiver_addr,
        amount
    );
    Commitment expected_commit = Commitment::Blinded(blind, amount);

    // Verify bulletproof
    ProofData proof_data = output.BuildProofData();
    REQUIRE(proof_data.commitment == expected_commit);
    REQUIRE(proof_data.pRangeProof == output.GetRangeProof());
    REQUIRE(Bulletproofs::BatchVerify({ output.BuildProofData() }));

    // Verify sender signature
    SignedMessage signed_msg = output.BuildSignedMsg();
    REQUIRE(signed_msg.GetPublicKey() == PublicKey::From(sender_key));
    REQUIRE(Schnorr::BatchVerify({ signed_msg }));

    // Getters
    REQUIRE_FALSE(output.IsPeggedIn());
    REQUIRE(output.GetCommitment() == expected_commit);
    REQUIRE(output.GetFeatures() == features);
    REQUIRE(output.ToOutputId() == OutputId(
        expected_commit,
        features,
        output.GetReceiverPubKey(),
        output.GetKeyExchangePubKey(),
        output.GetViewTag(),
        output.GetMaskedValue(),
        output.GetMaskedNonce(),
        output.GetSenderPubKey()
    ));

    //
    // Test Restoring Output
    //
    {
        // Check view tag
        SecretKey t = Hashed(EHashTag::DERIVE, output.Ke().Mul(a));
        REQUIRE(t[0] == output.GetViewTag());

        // Make sure B belongs to wallet
        REQUIRE(receiver_addr.B() == output.Ko().Sub(Hashed(EHashTag::OUT_KEY, t)));

        Deserializer hash64(Hash512(t).vec());
        SecretKey r = hash64.Read<SecretKey>();
        uint64_t value = output.GetMaskedValue() ^ hash64.Read<uint64_t>();
        BigInt<16> n = output.GetMaskedNonce() ^ hash64.ReadVector(16);

        REQUIRE(Commitment::Switch(r, value) == output.GetCommitment());

        // Calculate Carol's sending key 's' and check that s*B ?= Ke
        SecretKey s = Hasher(EHashTag::SEND_KEY)
            .Append(receiver_addr.A())
            .Append(receiver_addr.B())
            .Append(value)
            .Append(n)
            .hash();
        REQUIRE(output.Ke() == receiver_addr.B().Mul(s));

        // Make sure receiver can generate the spend key
        SecretKey spend_key = Crypto::AddPrivateKeys(b, Hashed(EHashTag::OUT_KEY, t));
        REQUIRE(output.GetReceiverPubKey() == PublicKey::From(spend_key));
    }
}