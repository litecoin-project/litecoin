// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/db/CoinDB.h>
#include <mw/db/LeafDB.h>
#include <mw/db/MMRInfoDB.h>
#include <mw/node/CoinsView.h>

#include <test_framework/TestMWEB.h>
#include <test_framework/models/Tx.h>

#include <limits>

namespace {

struct UnformattedValue
{
    std::vector<uint8_t> bytes;

    UnformattedValue() = default;
    explicit UnformattedValue(std::vector<uint8_t> bytes_in) : bytes(std::move(bytes_in)) {}

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s.write(MakeByteSpan(bytes));
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        bytes.resize(s.size());
        s.read(MakeWritableByteSpan(bytes));
    }
};

bool ReadUnformattedValue(CDBWrapper* pDatabase, const std::string& key, std::vector<uint8_t>& bytes)
{
    UnformattedValue value;
    if (!pDatabase->Read(key, value)) {
        return false;
    }

    bytes = std::move(value.bytes);
    return true;
}

void WriteLegacyMWEBValue(CDBWrapper* pDatabase, const std::string& key, const std::vector<uint8_t>& payload)
{
    BOOST_REQUIRE(pDatabase->Write(key, payload));

    std::vector<uint8_t> stored_value;
    BOOST_REQUIRE(ReadUnformattedValue(pDatabase, key, stored_value));
    BOOST_REQUIRE(stored_value != payload);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(TestCoinDB, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(MWEBDBValueFormatMigration)
{
    CDBWrapper* pDatabase = GetDB();

    const mmr::Leaf leaf = mmr::Leaf::Create(mmr::LeafIndex::At(0), {7, 8, 9});
    const std::vector<uint8_t> leaf_payload{3, 7, 8, 9};
    WriteLegacyMWEBValue(pDatabase, "O0", leaf_payload);

    const MMRInfo mmr_info{1, 0, mw::Hash(), 0, std::nullopt};
    const std::vector<uint8_t> mmr_info_payload = mmr_info.Serialized();
    WriteLegacyMWEBValue(pDatabase, "M0", mmr_info_payload);
    WriteLegacyMWEBValue(pDatabase, "M" + std::to_string(std::numeric_limits<uint32_t>::max()), mmr_info_payload);

    const test::Tx tx = test::Tx::CreatePegIn(1000);
    const mw::Coin::CPtr coin = std::make_shared<mw::Coin>(
        100,
        mmr::LeafIndex::At(0),
        tx.GetOutputs().front().GetOutput()
    );
    const std::string coin_key = "U" + coin->GetOutputID().ToHex();
    const std::vector<uint8_t> coin_payload = coin->Serialized();
    WriteLegacyMWEBValue(pDatabase, coin_key, coin_payload);

    const std::string non_mweb_key{"X0"};
    const std::vector<uint8_t> non_mweb_value{1, 2, 3};
    BOOST_REQUIRE(pDatabase->Write(non_mweb_key, non_mweb_value));
    std::vector<uint8_t> non_mweb_raw_before;
    BOOST_REQUIRE(ReadUnformattedValue(pDatabase, non_mweb_key, non_mweb_raw_before));

    const std::vector<std::string> invalid_mweb_keys{
        "Mbad",
        "M" + std::string(11, '1'),
        "O1x",
        "U" + std::string(63, '0') + "g"
    };
    const std::vector<uint8_t> invalid_mweb_value{4, 5, 6};
    std::vector<std::vector<uint8_t>> invalid_mweb_raw_before;
    for (const std::string& invalid_mweb_key : invalid_mweb_keys) {
        WriteLegacyMWEBValue(pDatabase, invalid_mweb_key, invalid_mweb_value);
        invalid_mweb_raw_before.emplace_back();
        BOOST_REQUIRE(ReadUnformattedValue(pDatabase, invalid_mweb_key, invalid_mweb_raw_before.back()));
    }

    auto pView = mw::CoinsViewDB::Open(m_path_root, nullptr, pDatabase);
    BOOST_REQUIRE(pView != nullptr);

    std::vector<uint8_t> raw_value;
    BOOST_REQUIRE(ReadUnformattedValue(pDatabase, std::string{"O0"}, raw_value));
    BOOST_CHECK(raw_value == leaf_payload);

    BOOST_REQUIRE(ReadUnformattedValue(pDatabase, std::string{"M0"}, raw_value));
    BOOST_CHECK(raw_value == mmr_info_payload);

    BOOST_REQUIRE(ReadUnformattedValue(pDatabase, coin_key, raw_value));
    BOOST_CHECK(raw_value == coin_payload);

    LeafDB leaf_db('O', pDatabase);
    auto pLeaf = leaf_db.Get(mmr::LeafIndex::At(0));
    BOOST_REQUIRE(pLeaf != nullptr);
    BOOST_CHECK(pLeaf->GetHash() == leaf.GetHash());
    BOOST_CHECK(pLeaf->vec() == leaf.vec());

    MMRInfoDB mmr_info_db(pDatabase);
    auto pMMRInfo = mmr_info_db.GetByIndex(0);
    BOOST_REQUIRE(pMMRInfo != nullptr);
    BOOST_CHECK_EQUAL(pMMRInfo->version, mmr_info.version);
    BOOST_CHECK_EQUAL(pMMRInfo->index, mmr_info.index);
    BOOST_CHECK(pMMRInfo->pruned == mmr_info.pruned);
    BOOST_CHECK_EQUAL(pMMRInfo->compact_index, mmr_info.compact_index);
    BOOST_CHECK(pMMRInfo->compacted == mmr_info.compacted);

    auto pLatestMMRInfo = mmr_info_db.GetLatest();
    BOOST_REQUIRE(pLatestMMRInfo != nullptr);
    BOOST_CHECK_EQUAL(pLatestMMRInfo->index, mmr_info.index);

    CoinDB coin_db(pDatabase);
    const auto coins = coin_db.GetCoins({coin->GetOutputID()});
    auto coin_iter = coins.find(coin->GetOutputID());
    BOOST_REQUIRE(coin_iter != coins.cend());
    BOOST_CHECK_EQUAL(coin_iter->second->GetBlockHeight(), coin->GetBlockHeight());
    BOOST_CHECK(coin_iter->second->GetLeafIndex() == coin->GetLeafIndex());
    BOOST_CHECK(coin_iter->second->GetOutput() == coin->GetOutput());

    std::vector<uint8_t> non_mweb_raw_after;
    BOOST_REQUIRE(ReadUnformattedValue(pDatabase, non_mweb_key, non_mweb_raw_after));
    BOOST_CHECK(non_mweb_raw_after == non_mweb_raw_before);

    std::vector<uint8_t> non_mweb_typed_after;
    BOOST_REQUIRE(pDatabase->Read(non_mweb_key, non_mweb_typed_after));
    BOOST_CHECK(non_mweb_typed_after == non_mweb_value);

    for (size_t i = 0; i < invalid_mweb_keys.size(); ++i) {
        std::vector<uint8_t> invalid_mweb_raw_after;
        BOOST_REQUIRE(ReadUnformattedValue(pDatabase, invalid_mweb_keys[i], invalid_mweb_raw_after));
        BOOST_CHECK(invalid_mweb_raw_after == invalid_mweb_raw_before[i]);

        std::vector<uint8_t> invalid_mweb_typed_after;
        BOOST_REQUIRE(pDatabase->Read(invalid_mweb_keys[i], invalid_mweb_typed_after));
        BOOST_CHECK(invalid_mweb_typed_after == invalid_mweb_value);
    }

    uint8_t db_format{0};
    BOOST_REQUIRE(pDatabase->Read(std::string{"mweb/db_format"}, db_format));
    BOOST_CHECK_EQUAL(db_format, 1);

    std::vector<uint8_t> progress_key;
    BOOST_CHECK(!pDatabase->Read(std::string{"mweb/db_migration_progress"}, progress_key));

    pView = mw::CoinsViewDB::Open(m_path_root, nullptr, pDatabase);
    BOOST_REQUIRE(pView != nullptr);

    BOOST_REQUIRE(ReadUnformattedValue(pDatabase, std::string{"O0"}, raw_value));
    BOOST_CHECK(raw_value == leaf_payload);
    BOOST_REQUIRE(ReadUnformattedValue(pDatabase, coin_key, raw_value));
    BOOST_CHECK(raw_value == coin_payload);
}

BOOST_AUTO_TEST_CASE(MWEBDBValueFormatMigrationFailsOnUndecodableRow)
{
    CDBWrapper* pDatabase = GetDB();

    const std::vector<uint8_t> invalid_legacy_value{0xff};
    BOOST_REQUIRE(pDatabase->Write(std::string{"O1"}, UnformattedValue(invalid_legacy_value)));

    BOOST_CHECK_THROW(
        mw::CoinsViewDB::Open(m_path_root, nullptr, pDatabase),
        dbwrapper_error
    );
}

BOOST_AUTO_TEST_SUITE_END()
