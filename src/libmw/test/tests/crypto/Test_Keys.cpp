// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/crypto/Blinds.h>
#include <mw/crypto/Keys.h>
#include <mw/crypto/SecretKeys.h>
#include <mw/exceptions/CryptoException.h>

#include <test_framework/TestMWEB.h>

static constexpr char CURVE_ORDER_HEX[] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
static constexpr char CURVE_ORDER_PLUS_ONE_HEX[] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142";
static constexpr char ONE_HEX[] = "0000000000000000000000000000000000000000000000000000000000000001";

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

BOOST_AUTO_TEST_CASE(SecretKeysFromNormalizesRange)
{
    SecretKey reduced = SecretKeys::From(SecretKey::FromHex(CURVE_ORDER_PLUS_ONE_HEX)).Total();
    BOOST_REQUIRE(reduced == SecretKey::FromHex(ONE_HEX));

    BOOST_CHECK_THROW(SecretKeys::From(SecretKey::FromHex(CURVE_ORDER_HEX)), CryptoException);
    BOOST_CHECK_THROW(SecretKeys::From(SecretKey::Null()), CryptoException);
}

BOOST_AUTO_TEST_CASE(SecretKeyFromHashValidation)
{
    std::vector<uint8_t> zero(32, 0);
    BOOST_REQUIRE(!SecretKey(zero).IsValid());
    BOOST_REQUIRE(SecretKey::FromHash(mw::Hash(zero)).IsValid());

    std::vector<uint8_t> one(32, 0);
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

BOOST_AUTO_TEST_CASE(PublicKeyValidation)
{
    BOOST_REQUIRE(PublicKey::Random().IsValid());

    std::vector<uint8_t> uncompressed(33, 0);
    uncompressed.front() = 0x04;
    BOOST_REQUIRE(!PublicKey(uncompressed.data()).IsValid());

    std::vector<uint8_t> invalid_compressed(33, 0xff);
    invalid_compressed.front() = 0x02;
    BOOST_REQUIRE(!PublicKey(invalid_compressed.data()).IsValid());
}

BOOST_AUTO_TEST_SUITE_END()
