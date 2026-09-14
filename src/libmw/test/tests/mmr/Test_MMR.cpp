// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/mmr/MMR.h>
#include <memusage.h>

#include <test_framework/TestMWEB.h>

using namespace mmr;

BOOST_FIXTURE_TEST_SUITE(TestMMR, MWEBTestingSetup)

// Rewinds release removed leaf payloads and hash bytes but retain vector capacity; flushing releases that capacity and preserves the MMR.
BOOST_AUTO_TEST_CASE(PMMRCache_MemoryUsage)
{
    auto disk = PMMR::Open('O', m_path_root / "mmr", 0, GetDB(), nullptr);
    auto parent = std::make_shared<PMMRCache>(disk);
    PMMRCache child(parent);
    const size_t empty_usage = child.DynamicMemoryUsage();
    std::vector<uint8_t> first(32, 1), second(64, 2), third(96, 3);
    third.reserve(1024); // Accounting must measure the stored copy.
    child.Add(first);
    child.Add(second);
    const auto root = child.Root();
    child.Add(third);
    const size_t full_usage = child.DynamicMemoryUsage();
    const size_t third_usage = memusage::DynamicUsage(child.GetLeaf(LeafIndex::At(2)).vec());
    const size_t hash_usage = memusage::DynamicUsage(child.GetHash(Index::At(0)).vec());
    BOOST_CHECK_GT(full_usage, memusage::DynamicUsage(first) + memusage::DynamicUsage(second) + third_usage + 7 * hash_usage);
    BOOST_CHECK_EQUAL(parent->DynamicMemoryUsage(), empty_usage);
    child.Rewind(2);
    BOOST_CHECK_EQUAL(child.DynamicMemoryUsage(), full_usage - third_usage - 2 * hash_usage);
    BOOST_CHECK(child.Root() == root);
    child.Rewind(0);
    BOOST_CHECK_EQUAL(child.DynamicMemoryUsage(), full_usage - third_usage -
        memusage::DynamicUsage(first) - memusage::DynamicUsage(second) - 7 * hash_usage);
    BOOST_CHECK_GT(child.DynamicMemoryUsage(), empty_usage);
    child.Add(first);
    child.Add(second);
    child.Flush(0, nullptr);
    BOOST_CHECK_EQUAL(child.DynamicMemoryUsage(), empty_usage);
    BOOST_CHECK_GT(parent->DynamicMemoryUsage(), empty_usage);
    BOOST_CHECK(child.Root() == root);
    BOOST_CHECK(parent->Root() == root);
    parent->Flush(1, nullptr);
    BOOST_CHECK_EQUAL(parent->DynamicMemoryUsage(), empty_usage);
    BOOST_CHECK(disk->Root() == root);
}

BOOST_AUTO_TEST_CASE(MMRTest)
{
    auto pmmr = PMMR::Open(
        'O',
        m_path_root / "mmr",
        0,
        GetDB(),
        nullptr
    );

    std::vector<uint8_t> leaf0({ 0, 1, 2 });
    std::vector<uint8_t> leaf1({ 1, 2, 3 });
    std::vector<uint8_t> leaf2({ 2, 3, 4 });
    std::vector<uint8_t> leaf3({ 3, 4, 5 });
    std::vector<uint8_t> leaf4({ 4, 5, 6 });

    pmmr->Add(leaf0);
    pmmr->Add(leaf1);
    pmmr->Add(leaf2);
    pmmr->Add(leaf3);

    BOOST_REQUIRE(pmmr->GetLeaf(LeafIndex::At(0)) == Leaf::Create(LeafIndex::At(0), leaf0));
    BOOST_REQUIRE(pmmr->GetLeaf(LeafIndex::At(1)) == Leaf::Create(LeafIndex::At(1), leaf1));
    BOOST_REQUIRE(pmmr->GetLeaf(LeafIndex::At(2)) == Leaf::Create(LeafIndex::At(2), leaf2));
    BOOST_REQUIRE(pmmr->GetLeaf(LeafIndex::At(3)) == Leaf::Create(LeafIndex::At(3), leaf3));

    BOOST_REQUIRE(pmmr->GetNumLeaves() == 4);
    BOOST_REQUIRE(pmmr->GetNumNodes() == 7);
    BOOST_CHECK_EQUAL(pmmr->Root().ToHex(), "9ab6e3c4a8594b9846b39b6beefe8f704c1de720f28426ddf3898bd4f8d6e45f");

    pmmr->Add(leaf4);
    BOOST_REQUIRE(pmmr->GetLeaf(LeafIndex::At(4)) == Leaf::Create(LeafIndex::At(4), leaf4));
    BOOST_REQUIRE(pmmr->GetNumLeaves() == 5);
    BOOST_REQUIRE(pmmr->GetNumNodes() == 8);
    BOOST_CHECK_EQUAL(pmmr->Root().ToHex(), "376ef1612abbb461ab78f317569c9a19d054f2c928c79410d50403564b91c5f7");

    pmmr->Rewind(4);
    BOOST_REQUIRE(pmmr->GetNumLeaves() == 4);
    BOOST_REQUIRE(pmmr->GetNumNodes() == 7);
    BOOST_CHECK_EQUAL(pmmr->Root().ToHex(), "9ab6e3c4a8594b9846b39b6beefe8f704c1de720f28426ddf3898bd4f8d6e45f");
}

BOOST_AUTO_TEST_CASE(PMMRCacheTest)
{
    PMMR::Ptr pmmr = PMMR::Open(
        'O',
        m_path_root / "mmr",
        0,
        GetDB(),
        nullptr
    );

    PMMRCache cache(pmmr);
    std::vector<uint8_t> leaf0({ 0, 1, 2 });
    std::vector<uint8_t> leaf1({ 1, 2, 3 });
    std::vector<uint8_t> leaf2({ 2, 3, 4 });
    std::vector<uint8_t> leaf3({ 3, 4, 5 });
    std::vector<uint8_t> leaf4({ 4, 5, 6 });

    cache.Add(leaf0);
    cache.Add(leaf1);
    cache.Add(leaf2);
    cache.Add(leaf3);

    BOOST_REQUIRE(cache.GetLeaf(LeafIndex::At(0)) == Leaf::Create(LeafIndex::At(0), leaf0));
    BOOST_REQUIRE(cache.GetLeaf(LeafIndex::At(1)) == Leaf::Create(LeafIndex::At(1), leaf1));
    BOOST_REQUIRE(cache.GetLeaf(LeafIndex::At(2)) == Leaf::Create(LeafIndex::At(2), leaf2));
    BOOST_REQUIRE(cache.GetLeaf(LeafIndex::At(3)) == Leaf::Create(LeafIndex::At(3), leaf3));

    BOOST_REQUIRE(cache.GetNumLeaves() == 4);
    BOOST_CHECK_EQUAL(cache.Root().ToHex(), "9ab6e3c4a8594b9846b39b6beefe8f704c1de720f28426ddf3898bd4f8d6e45f");

    cache.Add(leaf4);
    BOOST_REQUIRE(cache.GetLeaf(LeafIndex::At(4)) == Leaf::Create(LeafIndex::At(4), leaf4));
    BOOST_REQUIRE(cache.GetNumLeaves() == 5);
    BOOST_CHECK_EQUAL(cache.Root().ToHex(), "376ef1612abbb461ab78f317569c9a19d054f2c928c79410d50403564b91c5f7");

    cache.Rewind(4);
    BOOST_REQUIRE(cache.GetNumLeaves() == 4);
    BOOST_CHECK_EQUAL(cache.Root().ToHex(), "9ab6e3c4a8594b9846b39b6beefe8f704c1de720f28426ddf3898bd4f8d6e45f");

    cache.Flush(1, nullptr);
}

BOOST_AUTO_TEST_SUITE_END()
