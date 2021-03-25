#include <catch.hpp>

#include <mw/node/INode.h>
#include <mw/file/ScopedFileRemover.h>
#include <test_framework/Miner.h>
#include <test_framework/TestNode.h>

TEST_CASE("BlockValidator")
{
    FilePath datadir = test::TestUtil::GetTempDir();
    ScopedFileRemover remover(datadir); // Removes the directory when this goes out of scope.

    {
        test::Miner miner;

        // Block 10
        std::vector<test::Tx> block_10_txs{
            test::Tx::CreatePegIn(5'000'000)
        };

        std::vector<PegInCoin> pegInCoins{
            PegInCoin(5'000'000, block_10_txs[0].GetTransaction()->GetKernels()[0].GetCommitment())
        };
        std::vector<PegOutCoin> pegOutCoins;
        test::MinedBlock block_10 = miner.MineBlock(10, block_10_txs);

        mw::INode::Ptr pNode = test::CreateNode(datadir);

        REQUIRE_FALSE(block_10.GetBlock()->WasValidated());
        pNode->ValidateBlock(block_10.GetBlock(), block_10.GetHash(), pegInCoins, pegOutCoins);
        REQUIRE(block_10.GetBlock()->WasValidated());
    }
}