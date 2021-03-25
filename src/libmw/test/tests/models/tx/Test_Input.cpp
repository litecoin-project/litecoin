#include <catch.hpp>

#include <mw/crypto/Crypto.h>
#include <mw/crypto/Random.h>
#include <mw/models/tx/Input.h>

TEST_CASE("Plain Tx Input")
{
    Commitment commit(Random::CSPRNG<33>().GetBigInt());
    PublicKey pubkey(Random::CSPRNG<33>().GetBigInt());
    Signature signature(Random::CSPRNG<64>().GetBigInt());
    Input input(commit, pubkey, signature);

    //
    // Serialization
    //
    {
        std::vector<uint8_t> serialized = input.Serialized();

        Deserializer deserializer(serialized);
        REQUIRE(Commitment::Deserialize(deserializer) == commit);
        REQUIRE(PublicKey::Deserialize(deserializer) == pubkey);
        REQUIRE(Signature::Deserialize(deserializer) == signature);

        Deserializer deserializer2(serialized);
        REQUIRE(input == Input::Deserialize(deserializer2));

        REQUIRE(input.GetHash() == Hashed(serialized));
    }

    //
    // Getters
    //
    {
        REQUIRE(input.GetCommitment() == commit);
        REQUIRE(input.GetSignature() == signature);
    }
}