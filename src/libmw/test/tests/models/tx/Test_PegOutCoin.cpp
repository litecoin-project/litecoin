#include <catch.hpp>

#include <mw/crypto/Crypto.h>
#include <mw/crypto/Random.h>
#include <mw/models/tx/PegOutCoin.h>

TEST_CASE("Tx Peg-Out Coin")
{
    uint64_t amount = 123;
    std::vector<uint8_t> scriptPubKey = Random::CSPRNG<32>().vec();
    PegOutCoin pegOutCoin(amount, scriptPubKey);

    //
    // Serialization
    //
    {
        std::vector<uint8_t> serialized = pegOutCoin.Serialized();

        Deserializer deserializer(serialized);
        REQUIRE(deserializer.Read<uint64_t>() == amount);
        REQUIRE(deserializer.Read<uint8_t>() == 32);
        REQUIRE(deserializer.ReadVector(32) == scriptPubKey);

        Deserializer deserializer2(serialized);
        REQUIRE(pegOutCoin == PegOutCoin::Deserialize(deserializer2));
    }

    //
    // Getters
    //
    {
        REQUIRE(pegOutCoin.GetAmount() == amount);
        REQUIRE(pegOutCoin.GetScriptPubKey() == scriptPubKey);
    }
}