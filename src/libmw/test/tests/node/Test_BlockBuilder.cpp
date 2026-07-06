// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/node/BlockBuilder.h>
#include <mw/node/CoinsView.h>
#include <mw/node/BlockValidator.h>

#include <test_framework/Miner.h>
#include <test_framework/TestMWEB.h>
#include <test_framework/TxBuilder.h>

using namespace mw;

BOOST_FIXTURE_TEST_SUITE(TestBlockBuilder, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(BlockBuilder)
{
    auto db_view = CoinsViewDB::Open(m_path_root, nullptr, GetDB());
    auto cached_view = std::make_shared<CoinsViewCache>(db_view);

    test::Miner miner(m_path_root);

    ///////////////////////
    // Mine Block 1
    ///////////////////////
    test::Tx block1_tx1 = test::Tx::CreatePegIn(1000);
    auto block1 = miner.MineBlock(150, { block1_tx1 });
    cached_view->ApplyBlock(block1.GetBlock());

    ///////////////////////
    // Mine Block 2
    ///////////////////////
    test::Tx block2_tx1 = test::Tx::CreatePegIn(500);
    auto block2 = miner.MineBlock(151, {block2_tx1});
    cached_view->ApplyBlock(block2.GetBlock());

    ///////////////////////
    // Flush View
    ///////////////////////
    CDBBatch batch(*GetDB());
    cached_view->Flush(&batch);
    GetDB()->WriteBatch(batch);

    ///////////////////////
    // BlockBuilder
    ///////////////////////
    auto block_builder = std::make_shared<mw::BlockBuilder>(152, cached_view);

    test::Tx builder_tx1 = test::Tx::CreatePegIn(150);
    bool tx1_status = block_builder->AddTransaction(
        builder_tx1.GetTransaction(),
        { builder_tx1.GetPegInCoin() }
    );
    BOOST_CHECK(tx1_status);

    mw::Block::Ptr built_block = block_builder->BuildBlock();
    BOOST_CHECK(built_block->GetKernels().front() == builder_tx1.GetKernels().front());
    bool block_valid = BlockValidator::ValidateBlock(
        built_block,
        std::vector<PegInCoin>{ builder_tx1.GetPegInCoin() },
        std::vector<PegOutCoin>{}
    );
    BOOST_CHECK(block_valid);
}

BOOST_AUTO_TEST_CASE(BlockBuilderAllowsSpendOfStagedOutput)
{
    auto db_view = CoinsViewDB::Open(m_path_root, nullptr, GetDB());
    auto cached_view = std::make_shared<CoinsViewCache>(db_view);

    auto block_builder = std::make_shared<mw::BlockBuilder>(150, cached_view);

    test::Tx pegin_tx = test::Tx::CreatePegIn(1000);
    BOOST_CHECK(block_builder->AddTransaction(
        pegin_tx.GetTransaction(),
        { pegin_tx.GetPegInCoin() }
    ));

    test::Tx spend_tx = test::TxBuilder()
        .AddInput(pegin_tx.GetOutputs().front())
        .AddOutput(900)
        .AddPegoutKernel(100, 0)
        .Build();
    BOOST_CHECK(block_builder->AddTransaction(spend_tx.GetTransaction(), {}));
}

BOOST_AUTO_TEST_CASE(BlockBuilderRejectsDuplicateStagedInputs)
{
    auto db_view = CoinsViewDB::Open(m_path_root, nullptr, GetDB());
    auto cached_view = std::make_shared<CoinsViewCache>(db_view);

    test::Miner miner(m_path_root);
    test::Tx pegin_tx = test::Tx::CreatePegIn(1000);
    auto block = miner.MineBlock(150, { pegin_tx });
    cached_view->ApplyBlock(block.GetBlock());

    auto block_builder = std::make_shared<mw::BlockBuilder>(151, cached_view);

    test::Tx spend_tx1 = test::Tx::CreatePegOut(pegin_tx.GetOutputs().front());
    BOOST_CHECK(block_builder->AddTransaction(spend_tx1.GetTransaction(), {}));

    test::Tx spend_tx2 = test::Tx::CreatePegOut(pegin_tx.GetOutputs().front());
    BOOST_CHECK(!block_builder->AddTransaction(spend_tx2.GetTransaction(), {}));
}

BOOST_AUTO_TEST_SUITE_END()
