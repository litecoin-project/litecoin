#include <catch.hpp>

#include <mw/crypto/Crypto.h>
#include <mw/crypto/Random.h>
#include <mw/models/tx/UTXO.h>
#include <mw/models/wallet/StealthAddress.h>

TEST_CASE("Tx UTXO")
{
    uint64_t amount = 12345;
    BlindingFactor blind;
    Output output = Output::Create(
        blind,
        EOutputFeatures::DEFAULT_OUTPUT,
        Random::CSPRNG<32>(),
        StealthAddress::Random(),
        amount
    );
    Commitment commit = Crypto::CommitBlinded(amount, blind);

    uint64_t blockHeight = 20;
    mmr::LeafIndex leafIndex = mmr::LeafIndex::At(5);
    UTXO utxo{
        blockHeight,
        mmr::LeafIndex(leafIndex),
        Output(output)
    };

    //
    // Serialization
    //
    {
        std::vector<uint8_t> serialized = utxo.Serialized();

        Deserializer deserializer(serialized);
        REQUIRE(deserializer.Read<uint64_t>() == blockHeight);
        REQUIRE(mmr::LeafIndex::At(deserializer.Read<uint64_t>()) == leafIndex);
        REQUIRE(Output::Deserialize(deserializer) == output);
    }

    //
    // Getters
    //
    {
        REQUIRE(utxo.GetBlockHeight() == blockHeight);
        REQUIRE(utxo.GetLeafIndex() == leafIndex);
        REQUIRE(utxo.GetOutput() == output);
        REQUIRE(utxo.GetCommitment() == Crypto::CommitBlinded(amount, blind));
        REQUIRE(utxo.GetRangeProof() == output.GetRangeProof());
        REQUIRE(utxo.BuildProofData() == output.BuildProofData());
    }
}