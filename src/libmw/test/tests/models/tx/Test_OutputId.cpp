#include <catch.hpp>

#include <mw/crypto/Crypto.h>
#include <mw/crypto/Random.h>
#include <mw/models/tx/OutputId.h>

TEST_CASE("Tx Output Identifier")
{
    Commitment commit = Random::CSPRNG<33>().GetBigInt();
    EOutputFeatures features = EOutputFeatures::DEFAULT_OUTPUT;
    PublicKey receiverPubKey = Random::CSPRNG<33>().GetBigInt();
    PublicKey exchangePubKey = Random::CSPRNG<33>().GetBigInt();
    uint8_t viewTag = 100;
    uint64_t maskedValue = 123456789;
    BigInt<16> maskedNonce = Random::CSPRNG<16>().GetBigInt();
    PublicKey senderPubKey = Random::CSPRNG<33>().GetBigInt();
    OutputId outputId(
        commit,
        features,
        receiverPubKey,
        exchangePubKey,
        viewTag,
        maskedValue,
        maskedNonce,
        senderPubKey
    );

    //
    // Serialization
    //
    {
        std::vector<uint8_t> serialized = outputId.Serialized();
        REQUIRE(serialized.size() == 158);

        Deserializer deserializer(serialized);
        REQUIRE(deserializer.Read<Commitment>() == commit);
        REQUIRE(deserializer.Read<uint8_t>() == features);
        REQUIRE(deserializer.Read<PublicKey>() == receiverPubKey);
        REQUIRE(deserializer.Read<PublicKey>() == exchangePubKey);
        REQUIRE(deserializer.Read<uint8_t>() == viewTag);
        REQUIRE(deserializer.Read<uint64_t>() == maskedValue);
        REQUIRE(deserializer.Read<BigInt<16>>() == maskedNonce);
        REQUIRE(deserializer.Read<PublicKey>() == senderPubKey);

        Deserializer deserializer2(serialized);
        REQUIRE(outputId == OutputId::Deserialize(deserializer2));

        REQUIRE(outputId.GetHash() == Hashed(serialized));
    }

    //
    // Getters
    //
    {
        REQUIRE_FALSE(outputId.IsPeggedIn());
        //REQUIRE(outputId.GetFeatures() == features);
        REQUIRE(outputId.GetCommitment() == commit);
    }
}