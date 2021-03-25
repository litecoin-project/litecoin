#include <catch.hpp>

#include <mw/file/ScopedFileRemover.h>
#include <mw/mmr/PruneList.h>

#include <test_framework/TestUtil.h>

TEST_CASE("mmr::PruneList")
{
    FilePath tempDir = test::TestUtil::GetTempDir();
    ScopedFileRemover remover(tempDir);

    // Bitset: 00100000 01000000 00000000 00110011 11111111 100000000
    File(tempDir.GetChild("prun000009.dat"))
        .Write({ 0x20, 0x40, 0x00, 0x33, 0xff, 0x80 });

    mmr::PruneList::Ptr pPruneList = mmr::PruneList::Open(tempDir, 9);

    REQUIRE(pPruneList->GetTotalShift() == 15);
    REQUIRE(pPruneList->GetShift(mmr::Index::At(1)) == 0);
    REQUIRE(pPruneList->GetShift(mmr::Index::At(3)) == 1);
    REQUIRE(pPruneList->GetShift(mmr::Index::At(28)) == 4);
    REQUIRE(pPruneList->GetShift(mmr::Index::At(60)) == 15);
}