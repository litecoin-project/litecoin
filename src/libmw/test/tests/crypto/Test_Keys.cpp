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
}

BOOST_AUTO_TEST_CASE(SecretKeyValidation)
{
    std::vector<uint8_t> zero(SecretKey::SIZE, 0);
    BOOST_REQUIRE(!SecretKey(zero).IsValid());
    BOOST_REQUIRE(SecretKey::FromHash(mw::Hash(zero)).IsValid());

    std::vector<uint8_t> one(SecretKey::SIZE, 0);
    one.back() = 1;
    BOOST_REQUIRE(SecretKey(one).IsValid());
    BOOST_REQUIRE(SecretKey::FromHash(mw::Hash(one)) == SecretKey(one));

    std::vector<uint8_t> order{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
    };
    BOOST_REQUIRE(!SecretKey(order).IsValid());
    BOOST_REQUIRE(SecretKey::FromHash(mw::Hash(order)).IsValid());

    order.back()--;
    BOOST_REQUIRE(SecretKey(order).IsValid());
    BOOST_REQUIRE(SecretKey::FromHash(mw::Hash(order)) == SecretKey(order));
}

BOOST_AUTO_TEST_SUITE_END()
