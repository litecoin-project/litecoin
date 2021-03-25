#include <catch.hpp>

#include <mw/models/crypto/BigInteger.h>

TEST_CASE("BigInt")
{
    BigInt<8> bigInt1 = BigInt<8>::FromHex("0123456789AbCdEf");
    REQUIRE(bigInt1.ToHex() == "0123456789abcdef");
    REQUIRE(bigInt1.size() == 8);
    REQUIRE_FALSE(bigInt1.IsZero());
    REQUIRE(BigInt<8>().IsZero());
    REQUIRE(bigInt1.vec() == std::vector<uint8_t>({ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }));
    REQUIRE(bigInt1.ToArray() == std::array<uint8_t, 8>({ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }));

    BigInt<4> bigInt2 = BigInt<4>::Max();
    REQUIRE(bigInt2.ToHex() == "ffffffff");

    BigInt<8> bigInt3 = BigInt<8>::ValueOf(12);
    REQUIRE(bigInt3.ToHex() == "000000000000000c");

    REQUIRE(bigInt1[3] == 0x67);
    REQUIRE(bigInt1 > bigInt3);
    REQUIRE_FALSE(bigInt1 < bigInt3);
    REQUIRE_FALSE(bigInt1 < bigInt1);
    REQUIRE_FALSE(bigInt1 > bigInt1);
    REQUIRE(bigInt1 >= bigInt1);
    REQUIRE(bigInt1 <= bigInt1);
    REQUIRE(bigInt1 == bigInt1);
    REQUIRE_FALSE(bigInt1 != bigInt1);

    BigInt<8> bigInt4 = bigInt1;
    REQUIRE(bigInt1 == bigInt4);
    REQUIRE(bigInt1 != bigInt3);

    BigInt<8> bigInt5 = bigInt1.vec();
    REQUIRE(bigInt1 == bigInt5);
    bigInt5 = bigInt1.ToArray();
    REQUIRE(bigInt1 == bigInt5);
    bigInt5 = BigInt<8>(bigInt1.data());
    REQUIRE(bigInt1 == bigInt5);

    REQUIRE((bigInt1 ^ bigInt3).ToHex() == "0123456789abcde3");
    bigInt1 ^= bigInt3;
    REQUIRE(bigInt1.ToHex() == "0123456789abcde3");
    bigInt1 ^= bigInt3;
    REQUIRE(bigInt1.ToHex() == "0123456789abcdef");

    Deserializer deserializer = bigInt1.Serialized();
    BigInt<8> bigInt6 = BigInt<8>::Deserialize(deserializer);
    REQUIRE(bigInt1 == bigInt6);
}