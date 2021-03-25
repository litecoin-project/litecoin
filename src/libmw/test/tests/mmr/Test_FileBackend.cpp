#include <catch.hpp>

#include <mw/mmr/backends/FileBackend.h>
#include <mw/models/tx/Kernel.h>
#include <mw/crypto/Random.h>
#include <mw/file/ScopedFileRemover.h>

#include <test_framework/DBWrapper.h>
#include <test_framework/TestUtil.h>

using namespace mmr;

// TODO: Test with pruning
TEST_CASE("mmr::FileBackend")
{
    FilePath tempDir = test::TestUtil::GetTempDir();
    ScopedFileRemover remover(tempDir);
    
    {
        auto pDatabase = std::make_shared<TestDBWrapper>();

        {
            auto pBackend = FileBackend::Open('T', tempDir, 0, pDatabase, nullptr);
            pBackend->AddLeaf(mmr::Leaf::Create(mmr::LeafIndex::At(0), { 0x05, 0x03, 0x07 }));
            pBackend->Commit(1, nullptr);
        }
        {
            auto pBackend = FileBackend::Open('T', tempDir, 1, pDatabase, nullptr);
            REQUIRE(pBackend->GetNumLeaves() == 1);
            auto leaf = pBackend->GetLeaf(mmr::LeafIndex::At(0));
            REQUIRE(leaf.vec() == std::vector<uint8_t>{ 0x05, 0x03, 0x07 });
        }
    }
}