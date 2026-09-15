// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/mmr/MMR.h>
#include <mw/mmr/MMRUtil.h>
#include <mw/mmr/PruneList.h>
#include <mw/exceptions/NotFoundException.h>
#include <memusage.h>

#include <test_framework/TestMWEB.h>

using namespace mmr;

BOOST_FIXTURE_TEST_SUITE(TestMMR, MWEBTestingSetup)

// Repeated compaction preserves roots, retained hashes, appends and every rewind at or above the horizon.
BOOST_AUTO_TEST_CASE(PMMR_CompactionLifecycle)
{
    const FilePath dir(m_path_root / "mmr");
    auto disk = PMMR::Open('O', dir, 0, GetDB(), nullptr);
    PMMRCache cache(disk);
    std::vector<mw::Hash> roots{cache.Root()};
    for (uint8_t i = 0; i < 24; ++i) {
        cache.Add(std::vector<uint8_t>(32, i));
        roots.push_back(cache.Root());
    }
    cache.Flush(1, nullptr);
    BitSet retained(16);
    for (const size_t i : {2, 7, 12}) retained.set(i);
    const auto mask = MMRUtil::BuildCompactBitSet(16, retained);
    auto compact = disk->Compact(2, mask, 16);
    BOOST_CHECK_EQUAL(File(PMMR::GetPath(dir, 'O', 2)).GetSize(),
        (disk->GetNumNodes() - mask.count()) * mw::Hash::size());
    BOOST_CHECK(compact->Root() == roots.back());
    for (uint64_t i = 0; i < disk->GetNumNodes(); ++i) {
        const auto index = Index::At(i);
        if (mask.test(i)) BOOST_CHECK_THROW(compact->GetHash(index), NotFoundException);
        else BOOST_CHECK(compact->GetHash(index) == disk->GetHash(index));
    }
    for (uint64_t n = 16; n <= 24; ++n) {
        PMMRCache historical(compact);
        historical.Rewind(n);
        BOOST_CHECK(historical.Root() == roots[n]);
    }
    BOOST_CHECK_THROW(compact->Rewind(15), std::runtime_error);
    BOOST_CHECK(compact->Root() == roots.back());
    BOOST_CHECK_THROW(compact->Compact(2, mask, 16), std::runtime_error);
    BOOST_CHECK_THROW(compact->Compact(3, BitSet(32), 16), std::runtime_error);

    // Existing cache objects must continue reading the adopted base generation.
    disk->Adopt(*compact);
    BOOST_CHECK_THROW(cache.Rewind(15), std::runtime_error);
    BOOST_CHECK(cache.Root() == roots.back());
    cache.Add(std::vector<uint8_t>(32, 24));
    cache.Add(std::vector<uint8_t>(32, 25));
    const auto extended_root = cache.Root();
    cache.Flush(3, nullptr);
    auto reopened = PMMR::Open('O', dir, 3, GetDB(), PruneList::Open(dir, 2), 16);
    BOOST_CHECK_EQUAL(reopened->GetNumLeaves(), 26U);
    BOOST_CHECK(reopened->Root() == extended_root);
    retained = BitSet(24);
    retained.set(2);
    auto again = reopened->Compact(4, MMRUtil::BuildCompactBitSet(24, retained), 24);
    BOOST_CHECK(again->Root() == extended_root);
    BOOST_CHECK(again->GetLeaf(LeafIndex::At(2)) == reopened->GetLeaf(LeafIndex::At(2)));
    PMMRCache historical(again);
    historical.Rewind(24);
    BOOST_CHECK(historical.Root() == roots[24]);
    BOOST_CHECK_THROW(historical.Rewind(23), std::runtime_error);
}

// Streaming across multiple copy buffers retains the correct hashes and peaks when nearly all leaves are spent.
BOOST_AUTO_TEST_CASE(PMMR_CompactionStreaming)
{
    const FilePath dir(m_path_root / "mmr");
    auto disk = PMMR::Open('O', dir, 0, GetDB(), nullptr);
    PMMRCache cache(disk);
    constexpr uint64_t NUM_LEAVES{33000};
    for (uint64_t i = 0; i < NUM_LEAVES; ++i) cache.Add(std::vector<uint8_t>(32, i % 251));
    cache.Flush(1, nullptr);
    BitSet retained(NUM_LEAVES);
    for (const uint64_t i : {0, 127, 128, 16383, 16384, 32999}) retained.set(i);
    const auto mask = MMRUtil::BuildCompactBitSet(NUM_LEAVES, retained);
    const auto compact = disk->Compact(2, mask, NUM_LEAVES);
    BOOST_CHECK_EQUAL(compact->GetNumLeaves(), NUM_LEAVES);
    BOOST_CHECK(compact->Root() == disk->Root());
    for (uint64_t i = 0; i < disk->GetNumNodes(); ++i) {
        if (!mask.test(i)) BOOST_CHECK(compact->GetHash(Index::At(i)) == disk->GetHash(Index::At(i)));
    }
}

// A failed hash-file write leaves the active generation readable and permits retrying the orphaned generation.
BOOST_AUTO_TEST_CASE(PMMR_CompactionWriteFailure)
{
    const FilePath dir(m_path_root / "mmr");
    auto disk = PMMR::Open('O', dir, 0, GetDB(), nullptr);
    PMMRCache cache(disk);
    for (uint8_t i = 0; i < 8; ++i) cache.Add(std::vector<uint8_t>(32, i));
    cache.Flush(1, nullptr);
    const auto root = disk->Root();
    const auto mask = MMRUtil::BuildCompactBitSet(8, BitSet(8));
    const auto target = PMMR::GetPath(dir, 'O', 2);
    target.CreateDir();
    BOOST_CHECK_THROW(disk->Compact(2, mask, 8), FileException);
    BOOST_CHECK(disk->Root() == root);
    BOOST_CHECK(PMMR::Open('O', dir, 1, GetDB(), nullptr)->Root() == root);
    target.Remove();
    BOOST_CHECK(disk->Compact(2, mask, 8)->Root() == root);
}

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
