// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/crypto/Blinds.h>
#include <mw/crypto/Keys.h>

#include <test_framework/TestMWEB.h>

BOOST_FIXTURE_TEST_SUITE(TestKeys, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(KeysTest)
{
    SecretKey key1 = SecretKey::Random();
    SecretKey key2 = SecretKey::Random();
    SecretKey sum_keys = Blinds().Add(key1).Add(key2).ToKey();
    PublicKey pubsum1 = Keys::From(key1).Add(key2).PubKey();

    BOOST_REQUIRE(PublicKey::From(sum_keys) == pubsum1);

    BlindingFactor blind1 = BlindingFactor::FromHex("ef7ea7657149691b3df794f5eb8faa861a24e4a2e3bff60521f24fa4db7af933");
    BlindingFactor blind2 = BlindingFactor::FromHex("a89ac891d3cf82e9e08a8dac89b2c9c6ed54f0d7ba3c790d239aad76c42076f1");
    BlindingFactor blind_sum = Blinds().Add(blind1).Add(blind2).Total();
    BOOST_REQUIRE(blind_sum.ToHex() == "98196ff74518ec051e8222a27542744e4ccaf893eeb3ced685ba9e8ecf652ee3");
}

BOOST_AUTO_TEST_SUITE_END()