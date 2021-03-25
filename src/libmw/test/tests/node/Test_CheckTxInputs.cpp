#include <catch.hpp>

#include <libmw/libmw.h>
#include <mw/consensus/ChainParams.h>
#include <mw/crypto/Hasher.h>
#include <mw/file/ScopedFileRemover.h>
#include <mw/mmr/backends/FileBackend.h>
#include <mw/node/CoinsView.h>
#include <mw/node/INode.h>

#include <test_framework/DBWrapper.h>
#include <test_framework/Miner.h>
#include <test_framework/TestUtil.h>
#include <test_framework/TxBuilder.h>

TEST_CASE("CheckTxInputs")
{
    FilePath datadir = test::TestUtil::GetTempDir();
    ScopedFileRemover remover(datadir);

    auto pDatabase = std::make_shared<TestDBWrapper>();
    auto pNode = mw::InitializeNode(datadir, "test", nullptr, pDatabase);
    REQUIRE(pNode != nullptr);

    auto pDBView = pNode->GetDBView();
    auto pCachedView = libmw::CoinsViewRef{ std::make_shared<mw::CoinsViewCache>(pDBView) };

    test::Miner miner;
    uint64_t height = 100;

    // Mine pegin tx
    test::Tx tx1 = test::Tx::CreatePegIn(1000);
    auto block = miner.MineBlock(height, { tx1 });
    pNode->ValidateBlock(block.GetBlock(), block.GetHash(), { tx1.GetPegInCoin() }, {});
    pNode->ConnectBlock(block.GetBlock(), pCachedView.pCoinsView);
    height += mw::ChainParams::GetPegInMaturity();

    // Try to spend the pegin output
    const auto& output1 = tx1.GetOutputs().front();
    test::Tx tx2 = test::TxBuilder().AddInput(output1).AddPlainKernel(0).AddOutput(1000).Build();
    auto transaction = libmw::TxRef{ tx2.GetTransaction() };
    REQUIRE(libmw::node::CheckTransaction(transaction));
    REQUIRE_FALSE(libmw::node::CheckTxInputs(pCachedView, transaction, height - 1));
    REQUIRE(libmw::node::CheckTxInputs(pCachedView, transaction, height));

    // Try to spend an unknown pegin output
    test::Tx tx3 = test::Tx::CreatePegIn(1000);
    const auto& output2 = tx3.GetOutputs().front();
    test::Tx tx4 = test::TxBuilder().AddInput(output2).AddPlainKernel(0).AddOutput(1000).Build();
    transaction = libmw::TxRef{ tx4.GetTransaction() };
    REQUIRE(libmw::node::CheckTransaction(transaction));
    REQUIRE_FALSE(libmw::node::CheckTxInputs(pCachedView, transaction, height - 1));
    REQUIRE_FALSE(libmw::node::CheckTxInputs(pCachedView, transaction, height));

    pNode.reset();
}