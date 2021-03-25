#include <catch.hpp>

#include <libmw/libmw.h>
#include <mw/file/ScopedFileRemover.h>
#include <mw/node/validation/BlockValidator.h>

#include <test_framework/DBWrapper.h>
#include <test_framework/Miner.h>
#include <test_framework/TestUtil.h>

TEST_CASE("BlockBuilder")
{
    FilePath datadir = test::TestUtil::GetTempDir();
    ScopedFileRemover remover(datadir); // Removes the directory when this goes out of scope.

    {
        auto pDatabase = std::make_shared<TestDBWrapper>();
        libmw::ChainParams params{ datadir.u8string(), "test" };
        libmw::CoinsViewRef db_view = libmw::node::Initialize(params, libmw::HeaderRef{ nullptr }, pDatabase, {});
        libmw::CoinsViewRef cached_view = db_view.CreateCache();

        test::Miner miner;

        ///////////////////////
        // Mine Block 1
        ///////////////////////
        test::Tx block1_tx1 = test::Tx::CreatePegIn(1000);
        auto block1 = miner.MineBlock(150, { block1_tx1 });
        libmw::node::ConnectBlock(libmw::BlockRef{ block1.GetBlock() }, cached_view);

        ///////////////////////
        // Mine Block 2
        ///////////////////////
        test::Tx block2_tx1 = test::Tx::CreatePegIn(500);
        auto block2 = miner.MineBlock(151, { block2_tx1 });
        libmw::node::ConnectBlock(libmw::BlockRef{ block2.GetBlock() }, cached_view);

        ///////////////////////
        // Flush View
        ///////////////////////
        auto pBatch = pDatabase->CreateBatch();
        libmw::node::FlushCache(cached_view, pBatch);
        pBatch->Commit();

        ///////////////////////
        // BlockBuilder
        ///////////////////////
        libmw::BlockBuilderRef block_builder = libmw::miner::NewBuilder(152, cached_view);

        test::Tx builder_tx1 = test::Tx::CreatePegIn(150);
        libmw::PegIn builder_tx1_pegin{ 150, builder_tx1.GetKernels().front().GetCommitment().array() };
        bool tx1_status = libmw::miner::AddTransaction(
            block_builder,
            libmw::TxRef{ builder_tx1.GetTransaction() },
            { builder_tx1_pegin }
        );
        REQUIRE(tx1_status);

        libmw::BlockRef built_block = libmw::miner::BuildBlock(block_builder);
        REQUIRE(built_block.pBlock->GetKernels().front() == builder_tx1.GetKernels().front());
        BlockValidator().Validate(built_block.pBlock, built_block.pBlock->GetHash(), { builder_tx1.GetPegInCoin() }, {});

        libmw::node::Shutdown();
    }
}