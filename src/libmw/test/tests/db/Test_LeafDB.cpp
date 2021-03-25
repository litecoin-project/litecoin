#include <catch.hpp>

#include <mw/db/LeafDB.h>

#include <test_framework/DBWrapper.h>

TEST_CASE("LeafDB")
{
    auto pDatabase = std::make_shared<TestDBWrapper>();
    LeafDB ldb('L', pDatabase.get());

    auto leaf1 = mmr::Leaf::Create(mmr::LeafIndex::At(0), { 0, 1, 2 });
    auto leaf2 = mmr::Leaf::Create(mmr::LeafIndex::At(1), { 1, 2, 3 });
    auto leaf3 = mmr::Leaf::Create(mmr::LeafIndex::At(2), { 2, 3, 4 });

    ldb.Add({leaf1, leaf2, leaf3});

    auto pLeaf = ldb.Get(mmr::LeafIndex::At(0));
    REQUIRE(pLeaf->GetHash() == leaf1.GetHash());
    REQUIRE(pLeaf->vec() == leaf1.vec());

    pLeaf = ldb.Get(mmr::LeafIndex::At(1));
    REQUIRE(pLeaf->GetHash() == leaf2.GetHash());
    REQUIRE(pLeaf->vec() == leaf2.vec());

    pLeaf = ldb.Get(mmr::LeafIndex::At(2));
    REQUIRE(pLeaf->GetHash() == leaf3.GetHash());
    REQUIRE(pLeaf->vec() == leaf3.vec());

    std::vector<uint8_t> data;
    REQUIRE(pDatabase->Read("L" + std::to_string(leaf1.GetLeafIndex().Get()), data));
    REQUIRE(data == leaf1.vec());
    REQUIRE(pDatabase->Read("L" + std::to_string(leaf2.GetLeafIndex().Get()), data));
    REQUIRE(data == leaf2.vec());
    REQUIRE(pDatabase->Read("L" + std::to_string(leaf3.GetLeafIndex().Get()), data));
    REQUIRE(data == leaf3.vec());

    ldb.Remove({leaf2.GetLeafIndex()});
    REQUIRE(ldb.Get(mmr::LeafIndex::At(1)) == nullptr);

    ldb.RemoveAll();
    REQUIRE(ldb.Get(mmr::LeafIndex::At(0)) == nullptr);
    REQUIRE(ldb.Get(mmr::LeafIndex::At(2)) == nullptr);

    ldb.Add({leaf2});
    pLeaf = ldb.Get(mmr::LeafIndex::At(1));
    REQUIRE(pLeaf->GetHash() == leaf2.GetHash());
    REQUIRE(pLeaf->vec() == leaf2.vec());
}