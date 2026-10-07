// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/mmr/PruneList.h>
#include <mw/file/File.h>

#include <test_framework/TestMWEB.h>

BOOST_FIXTURE_TEST_SUITE(TestPruneList, MWEBTestingSetup)

// Cached ranks agree with a direct count across interval boundaries, byte padding and reopened files.
BOOST_AUTO_TEST_CASE(PruneList_LargeRanks)
{
    BitSet bits(1027);
    for (uint64_t i = 0; i < bits.size(); ++i) if (i % 3 == 0) bits.set(i);
    auto list = PruneList::Create(m_path_root);
    list->Commit(1, bits);
    for (const auto& candidate : {list, PruneList::Open(m_path_root, 1)}) {
        for (uint64_t i = 0; i < 1100; ++i) {
            if (!bits.test(i)) BOOST_CHECK_EQUAL(candidate->GetShift(mmr::Index::At(i)), bits.rank(i));
        }
    }
    list->Commit(2, BitSet{});
    BOOST_CHECK_EQUAL(list->GetShift(mmr::Index::At(1026)), 0U);
    BOOST_CHECK_EQUAL(PruneList::Open(m_path_root, 0)->GetTotalShift(), 0U);
    BOOST_CHECK_THROW(PruneList::Open(m_path_root, 3), FileException);
}

// Retrying an unpublished generation replaces its mask, including shorter and empty replacements.
BOOST_AUTO_TEST_CASE(PruneList_ReplacesOrphan)
{
    auto list = PruneList::Create(m_path_root);
    BitSet original(1027);
    original.set(1026);
    list->Commit(1, original);

    BitSet replacement(16);
    replacement.set(3);
    replacement.set(9);
    for (int retry = 0; retry < 2; ++retry) {
        list->Commit(1, replacement);
        BOOST_CHECK(File(PruneList::GetPath(m_path_root, 1)).ReadBytes() == replacement.bytes());
        const auto reopened = PruneList::Open(m_path_root, 1);
        BOOST_CHECK_EQUAL(reopened->GetTotalShift(), 2U);
        BOOST_CHECK_EQUAL(reopened->GetShift(mmr::Index::At(16)), 2U);
    }

    list->Commit(1, BitSet{});
    BOOST_CHECK_EQUAL(File(PruneList::GetPath(m_path_root, 1)).GetSize(), 0U);
    BOOST_CHECK_EQUAL(PruneList::Open(m_path_root, 1)->GetTotalShift(), 0U);
}

// Reopened masks translate logical positions by the number of preceding compacted hashes.
BOOST_AUTO_TEST_CASE(PruneListTest)
{
    // Bitset: 00100000 01000000 00000000 00110011 11111111 100000000
    File(m_path_root / "prun000009.dat")
        .Write({ 0x20, 0x40, 0x00, 0x33, 0xff, 0x80 });

    PruneList::Ptr pPruneList = PruneList::Open(m_path_root, 9);

    BOOST_REQUIRE(pPruneList->GetTotalShift() == 15);
    BOOST_REQUIRE(pPruneList->GetShift(mmr::Index::At(1)) == 0);
    BOOST_REQUIRE(pPruneList->GetShift(mmr::Index::At(3)) == 1);
    BOOST_REQUIRE(pPruneList->GetShift(mmr::Index::At(28)) == 4);
    BOOST_REQUIRE(pPruneList->GetShift(mmr::Index::At(60)) == 15);
}

BOOST_AUTO_TEST_SUITE_END()
