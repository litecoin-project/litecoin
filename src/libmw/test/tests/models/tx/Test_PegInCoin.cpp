#include <catch.hpp>

#include <mw/crypto/Crypto.h>
#include <mw/crypto/Random.h>
#include <mw/models/tx/PegInCoin.h>

TEST_CASE("Tx Peg-In Coin")
{
    uint64_t amount = 123;
    Commitment commit = Random::CSPRNG<33>().GetBigInt();
    PegInCoin pegInCoin(amount, commit);

    //
    // Serialization
    //
    {
        std::vector<uint8_t> serialized = pegInCoin.Serialized();
        REQUIRE(serialized.size() == 41);

        Deserializer deserializer(serialized);
        REQUIRE(deserializer.Read<uint64_t>() == amount);
        REQUIRE(Commitment::Deserialize(deserializer) == commit);

        Deserializer deserializer2(serialized);
        REQUIRE(pegInCoin == PegInCoin::Deserialize(deserializer2));
    }

    //
    // Getters
    //
    {
        REQUIRE(pegInCoin.GetAmount() == amount);
        REQUIRE(pegInCoin.GetCommitment() == commit);
    }
}