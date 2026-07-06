// Copyright (c) 2025 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/crypto/PublicKeys.h>
#include <mw/exceptions/CryptoException.h>

#include <test_framework/TestMWEB.h>

// Secret key with value greater than curve order
static constexpr char CURVE_ORDER_HEX[] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
static constexpr char VALID_SECRET_KEY_HEX[] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140";
static constexpr char INVALID_SECRET_KEY_HEX[] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142";

BOOST_FIXTURE_TEST_SUITE(TestPublicKey, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(PublicKeyArithmetic)
{
    // A CryptoException should be thrown when trying to calculate a PublicKey from a SecretKey with a value greater than the secp256k1 curve order.
    SecretKey invalid_sk = SecretKey::FromHex(INVALID_SECRET_KEY_HEX);
    BOOST_CHECK_THROW(PublicKey::From(invalid_sk), CryptoException);

    SecretKey curve_order_sk = SecretKey::FromHex(CURVE_ORDER_HEX);
    BOOST_CHECK_THROW(PublicKey::From(curve_order_sk), CryptoException);

    SecretKey valid_sk = SecretKey::FromHex(VALID_SECRET_KEY_HEX);
    BOOST_CHECK_NO_THROW(PublicKey::From(valid_sk));
}

BOOST_AUTO_TEST_SUITE_END()
