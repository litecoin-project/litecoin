// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/models/tx/Coin.h>
#include <mw/models/wallet/StealthAddress.h>

#include <test_framework/Deserializer.h>
#include <test_framework/TestMWEB.h>

BOOST_FIXTURE_TEST_SUITE(TestCoin, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(TxCoin)
{
    CAmount amount = 12345;
    BlindingFactor blind;
    mw::Output output = mw::Output::Create(
        &blind,
        SecretKey::Random(),
        SecretKey::Random(),
        StealthAddress::Random(),
        amount,
        std::vector<uint8_t>{}
    );
    Commitment commit = Commitment::Switch(blind, amount);

    int32_t blockHeight = 20;
    mmr::LeafIndex leafIndex = mmr::LeafIndex::At(5);
    mw::Coin coin{
        blockHeight,
        mmr::LeafIndex(leafIndex),
        mw::Output(output)
    };

    //
    // Serialization
    //
    {
        std::vector<uint8_t> serialized = coin.Serialized();

        Deserializer deserializer(serialized);
        BOOST_REQUIRE(deserializer.Read<int32_t>() == blockHeight);
        BOOST_REQUIRE(mmr::LeafIndex::At(deserializer.Read<uint64_t>()) == leafIndex);
        BOOST_REQUIRE(deserializer.Read<mw::Output>() == output);
    }

    //
    // Getters
    //
    {
        BOOST_REQUIRE(coin.GetBlockHeight() == blockHeight);
        BOOST_REQUIRE(coin.GetLeafIndex() == leafIndex);
        BOOST_REQUIRE(coin.GetOutput() == output);
        BOOST_REQUIRE(coin.GetCommitment() == commit);
        BOOST_REQUIRE(coin.GetRangeProof() == output.GetRangeProof());
        BOOST_REQUIRE(coin.BuildProofData() == output.BuildProofData());
    }
}

BOOST_AUTO_TEST_SUITE_END()
