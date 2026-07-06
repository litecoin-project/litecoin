// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/db/LeafDB.h>
#include <mw/db/CoinDB.h>
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

} // namespace

BOOST_FIXTURE_TEST_SUITE(TestLeafDB, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(LeafDBTest)
{
    auto pDatabase = GetDB();

    LeafDB ldb('L', pDatabase);

    auto leaf1 = mmr::Leaf::Create(mmr::LeafIndex::At(0), { 0, 1, 2 });
    auto leaf2 = mmr::Leaf::Create(mmr::LeafIndex::At(1), { 1, 2, 3 });
    auto leaf3 = mmr::Leaf::Create(mmr::LeafIndex::At(2), { 2, 3, 4 });

    ldb.Add({leaf1, leaf2, leaf3});

    auto pLeaf = ldb.Get(mmr::LeafIndex::At(0));
    BOOST_REQUIRE(pLeaf->GetHash() == leaf1.GetHash());
    BOOST_REQUIRE(pLeaf->vec() == leaf1.vec());

    pLeaf = ldb.Get(mmr::LeafIndex::At(1));
    BOOST_REQUIRE(pLeaf->GetHash() == leaf2.GetHash());
    BOOST_REQUIRE(pLeaf->vec() == leaf2.vec());

    pLeaf = ldb.Get(mmr::LeafIndex::At(2));
    BOOST_REQUIRE(pLeaf->GetHash() == leaf3.GetHash());
    BOOST_REQUIRE(pLeaf->vec() == leaf3.vec());

    std::vector<uint8_t> data;
    BOOST_REQUIRE(ReadUnformattedValue(pDatabase, "L" + std::to_string(leaf1.GetLeafIndex().Get()), data));
    BOOST_REQUIRE(data == std::vector<uint8_t>({3, 0, 1, 2}));

    BOOST_REQUIRE(ReadUnformattedValue(pDatabase, "L" + std::to_string(leaf2.GetLeafIndex().Get()), data));
    BOOST_REQUIRE(data == std::vector<uint8_t>({3, 1, 2, 3}));

    BOOST_REQUIRE(ReadUnformattedValue(pDatabase, "L" + std::to_string(leaf3.GetLeafIndex().Get()), data));
    BOOST_REQUIRE(data == std::vector<uint8_t>({3, 2, 3, 4}));

    ldb.Remove({leaf2.GetLeafIndex()});
    BOOST_REQUIRE(ldb.Get(mmr::LeafIndex::At(1)) == nullptr);

    ldb.Add({leaf2});
    pLeaf = ldb.Get(mmr::LeafIndex::At(1));
    BOOST_REQUIRE(pLeaf->GetHash() == leaf2.GetHash());
    BOOST_REQUIRE(pLeaf->vec() == leaf2.vec());
}

BOOST_AUTO_TEST_SUITE_END()
