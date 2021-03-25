#include <catch.hpp>

#include <mw/file/ScopedFileRemover.h>
#include <mw/node/CoinsView.h>
#include <mw/node/INode.h>

#include <test_framework/models/Tx.h>
#include <test_framework/DBWrapper.h>
#include <test_framework/Miner.h>
#include <test_framework/TestUtil.h>
#include <test_framework/TxBuilder.h>

TEST_CASE("ValidateState")
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

        // Block containing peg-ins only
        test::Tx tx1 = test::TxBuilder()
            .AddPeginKernel(50)
            .AddOutput(50, EOutputFeatures::PEGGED_IN)
            .AddPeginKernel(30)
            .AddOutput(30, EOutputFeatures::PEGGED_IN)
            .Build();

        std::vector<PegInCoin> pegInCoins = tx1.GetTransaction()->GetPegIns();

        auto block1 = miner.MineBlock(150, { tx1 });
        pNode->ValidateBlock(block1.GetBlock(), block1.GetHash(), pegInCoins, {});
        pNode->ConnectBlock(block1.GetBlock(), pCachedView);
        pCachedView->ValidateState();

        // Block containing peg-outs and regular sends only
        test::Tx tx2 = test::TxBuilder()
            .AddInput(50, EOutputFeatures::PEGGED_IN, tx1.GetOutputs().front().GetBlind())
            .AddPegoutKernel(15, 5)
            .AddPlainKernel(10)
            .AddOutput(20)
            .Build();

        std::vector<PegOutCoin> pegOutCoins = tx2.GetTransaction()->GetPegOuts();

        auto block2 = miner.MineBlock(151, { tx2 });
        pNode->ValidateBlock(block2.GetBlock(), block2.GetHash(), {}, pegOutCoins);
        pNode->ConnectBlock(block2.GetBlock(), pCachedView);
        pCachedView->ValidateState();

        pNode.reset();
    }
}