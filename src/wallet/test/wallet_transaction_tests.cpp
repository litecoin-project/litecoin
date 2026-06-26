// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/transaction.h>

#include <wallet/test/wallet_test_fixture.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(wallet_transaction_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(roundtrip)
{
    for (uint8_t hash = 0; hash < 5; ++hash) {
        for (int index = -2; index < 3; ++index) {
            TxState state = TxStateInterpretSerialized(TxStateUnrecognized{uint256{hash}, index});
            BOOST_CHECK_EQUAL(TxStateSerializedBlockHash(state), uint256{hash});
            BOOST_CHECK_EQUAL(TxStateSerializedIndex(state), index);
        }
    }
}

BOOST_AUTO_TEST_CASE(confirmed_position_semantics)
{
    const uint256 block_hash{uint256{2}};

    TxState normal = TxStateInterpretSerialized(TxStateUnrecognized{block_hash, 3});
    const auto* normal_confirmed = std::get_if<TxStateConfirmed>(&normal);
    BOOST_REQUIRE(normal_confirmed);
    BOOST_CHECK(normal_confirmed->HasPositionInBlock());
    BOOST_CHECK_EQUAL(normal_confirmed->position_in_block, 3);
    BOOST_CHECK_EQUAL(TxStateSerializedIndex(normal), 3);

    TxState mweb_only = TxStateInterpretSerialized(TxStateUnrecognized{block_hash, TxStateConfirmed::NO_POSITION_IN_BLOCK});
    const auto* mweb_confirmed = std::get_if<TxStateConfirmed>(&mweb_only);
    BOOST_REQUIRE(mweb_confirmed);
    BOOST_CHECK(!mweb_confirmed->HasPositionInBlock());
    BOOST_CHECK_EQUAL(TxStateSerializedIndex(mweb_only), TxStateConfirmed::NO_POSITION_IN_BLOCK);
    BOOST_CHECK_EQUAL(TxStateSerializedBlockHash(mweb_only), block_hash);

    TxState unknown_negative = TxStateInterpretSerialized(TxStateUnrecognized{block_hash, TxStateConfirmed::NO_POSITION_IN_BLOCK - 1});
    BOOST_CHECK(std::get_if<TxStateUnrecognized>(&unknown_negative));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
