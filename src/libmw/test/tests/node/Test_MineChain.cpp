#include <catch.hpp>

#include <mw/node/CoinsView.h>
#include <mw/crypto/Hasher.h>
#include <mw/file/ScopedFileRemover.h>
#include <mw/mmr/backends/FileBackend.h>
#include <mw/node/INode.h>

#include <test_framework/DBWrapper.h>
#include <test_framework/Miner.h>
#include <test_framework/TestUtil.h>

TEST_CASE("Mine Chain")
{
    FilePath datadir = test::TestUtil::GetTempDir();
    ScopedFileRemover remover(datadir); // Removes the directory when this goes out of scope.

    {
        auto pDatabase = std::make_shared<TestDBWrapper>();
        auto pNode = mw::InitializeNode(datadir, "test", nullptr, pDatabase);
        REQUIRE(pNode != nullptr);

        auto pDBView = pNode->GetDBView();
        auto pCachedView = std::make_shared<mw::CoinsViewCache>(pDBView);

        test::Miner miner;

        ///////////////////////
        // Mine Block 1
        ///////////////////////
        test::Tx block1_tx1 = test::Tx::CreatePegIn(1000);
        auto block1 = miner.MineBlock(150, { block1_tx1 });
        pNode->ValidateBlock(block1.GetBlock(), block1.GetHash(), { block1_tx1.GetPegInCoin() }, {});
        pNode->ConnectBlock(block1.GetBlock(), pCachedView);

        const auto& block1_tx1_output1 = block1_tx1.GetOutputs()[0];
        REQUIRE(pDBView->GetUTXOs(block1_tx1_output1.GetCommitment()).empty());
        REQUIRE(pCachedView->GetUTXOs(block1_tx1_output1.GetCommitment()).size() == 1);

        ///////////////////////
        // Mine Block 2
        ///////////////////////
        test::Tx block2_tx1 = test::Tx::CreatePegIn(500);
        auto block2 = miner.MineBlock(151, { block2_tx1 });
        pNode->ValidateBlock(block2.GetBlock(), block2.GetHash(), { block2_tx1.GetPegInCoin() }, {});
        pNode->ConnectBlock(block2.GetBlock(), pCachedView);

        const auto& block2_tx1_output1 = block2_tx1.GetOutputs()[0];
        REQUIRE(pDBView->GetUTXOs(block2_tx1_output1.GetCommitment()).empty());
        REQUIRE(pCachedView->GetUTXOs(block2_tx1_output1.GetCommitment()).size() == 1);

        ///////////////////////
        // Flush View
        ///////////////////////
        auto pBatch = pDatabase->CreateBatch();
        pCachedView->Flush(pBatch);
        pBatch->Commit();

        REQUIRE(pDBView->GetUTXOs(block1_tx1_output1.GetCommitment()).size() == 1);
        REQUIRE(pCachedView->GetUTXOs(block1_tx1_output1.GetCommitment()).size() == 1);
        REQUIRE(pDBView->GetUTXOs(block2_tx1_output1.GetCommitment()).size() == 1);
        REQUIRE(pCachedView->GetUTXOs(block2_tx1_output1.GetCommitment()).size() == 1);

        pNode.reset();
    }
}