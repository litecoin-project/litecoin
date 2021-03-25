#include <catch.hpp>

#include <mw/wallet/Keychain.h>
#include <libmw/libmw.h>

TEST_CASE("Keychain::GetStealthAddress")
{
    SecretKey a = BigInt<32>::FromHex("6a94ffabf7cb6c56b7f1bda50158019a49d101e270ad202e04912b2f001ece79");
    SecretKey b = BigInt<32>::FromHex("da5b685cbcdad4aabcec8f58253f8f4aa89a116659b1e5a8e3c407cc09c19738");

    StealthAddress address_100 = mw::Keychain(a, b, 50).GetStealthAddress(100);
    REQUIRE(address_100.A().Format() == "02676d6f55a58297072c602b9e3c98bdcf7f2632c4c88686bd8e8cf3f12d394111");
    REQUIRE(address_100.B().Format() == "03e7421b2c09154a4201072c733929dfc25262dd79146f1164b4b000c4f5533e01");
}