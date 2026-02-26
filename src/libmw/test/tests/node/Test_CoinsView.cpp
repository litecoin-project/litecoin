// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/node/CoinsView.h>
#include <mw/exceptions/ValidationException.h>
#include <mw/models/tx/MutableTx.h>

#include <test_framework/Miner.h>
#include <test_framework/TestMWEB.h>
#include <test_framework/TxBuilder.h>

using namespace mw;

BOOST_FIXTURE_TEST_SUITE(TestCoinsView, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(CoinsViewCache_ApplyBlock_InputCommitmentMismatch)
{
    auto pDBView = mw::CoinsViewDB::Open(m_path_root, nullptr, GetDB());
    BOOST_REQUIRE(pDBView != nullptr);

    auto pCachedView = std::make_shared<mw::CoinsViewCache>(pDBView);
    test::Miner miner(m_path_root);

    test::Tx funding_tx = test::TxBuilder()
        .AddPeginKernel(5'000'000)
        .AddOutput(5'000'000, SecretKey::Random(), StealthAddress::Random())
        .Build();
    pCachedView->ApplyBlock(miner.MineBlock(1, { funding_tx }).GetBlock());

    test::Tx spend_tx = test::TxBuilder()
        .AddInput(funding_tx.GetOutputs()[0])
        .AddOutput(5'000'000, SecretKey::Random(), StealthAddress::Random())
        .AddPlainKernel(0)
        .Build();
    mw::Block::CPtr pSpendBlock = miner.MineBlock(2, { spend_tx }).GetBlock();

    mw::MutableTx mutable_tx = mw::MutableTx::From(*spend_tx.GetTransaction());
    mutable_tx.inputs.front().commitment = Commitment::Transparent(5'000'000);
    mw::Transaction::CPtr pInvalidTx = mutable_tx.Finalized().value();

    mw::Block::CPtr pInvalidBlock = mw::MutBlock(pSpendBlock)
        .SetInputs(pInvalidTx->GetInputs())
        .SetOutputs(pInvalidTx->GetOutputs())
        .SetKernels(pInvalidTx->GetKernels())
        .Build();

    BOOST_REQUIRE_THROW(pCachedView->ApplyBlock(pInvalidBlock), ValidationException);
}

BOOST_AUTO_TEST_CASE(CoinsViewCache_ApplyBlock_InputPubKeyMismatch)
{
    auto pDBView = mw::CoinsViewDB::Open(m_path_root, nullptr, GetDB());
    BOOST_REQUIRE(pDBView != nullptr);

    auto pCachedView = std::make_shared<mw::CoinsViewCache>(pDBView);
    test::Miner miner(m_path_root);

    test::Tx funding_tx = test::TxBuilder()
        .AddPeginKernel(5'000'000)
        .AddOutput(5'000'000, SecretKey::Random(), StealthAddress::Random())
        .Build();
    pCachedView->ApplyBlock(miner.MineBlock(1, { funding_tx }).GetBlock());

    test::Tx spend_tx = test::TxBuilder()
        .AddInput(funding_tx.GetOutputs()[0])
        .AddOutput(5'000'000, SecretKey::Random(), StealthAddress::Random())
        .AddPlainKernel(0)
        .Build();
    mw::Block::CPtr pSpendBlock = miner.MineBlock(2, { spend_tx }).GetBlock();

    mw::MutableTx mutable_tx = mw::MutableTx::From(*spend_tx.GetTransaction());
    mutable_tx.inputs.front().output_pubkey = PublicKey::Random();
    mw::Transaction::CPtr pInvalidTx = mutable_tx.Finalized().value();

    mw::Block::CPtr pInvalidBlock = mw::MutBlock(pSpendBlock)
        .SetInputs(pInvalidTx->GetInputs())
        .SetOutputs(pInvalidTx->GetOutputs())
        .SetKernels(pInvalidTx->GetKernels())
        .Build();

    BOOST_REQUIRE_THROW(pCachedView->ApplyBlock(pInvalidBlock), ValidationException);
}

BOOST_AUTO_TEST_CASE(CoinsViewCache_ApplyBlock_InvalidOutputRoot)
{
    auto pDBView = mw::CoinsViewDB::Open(m_path_root, nullptr, GetDB());
    BOOST_REQUIRE(pDBView != nullptr);

    auto pCachedView = std::make_shared<mw::CoinsViewCache>(pDBView);
    test::Miner miner(m_path_root);

    test::Tx tx = test::Tx::CreatePegIn(5'000'000);
    mw::Block::CPtr pBlock = miner.MineBlock(1, { tx }).GetBlock();

    mw::Block::CPtr pInvalidBlock = std::make_shared<mw::Block>(
        mw::MutHeader(pBlock->GetHeader())
            .SetOutputRoot(SecretKey::Random().GetBigInt())
            .Build(),
        pBlock->GetTxBody()
    );

    BOOST_REQUIRE_THROW(pCachedView->ApplyBlock(pInvalidBlock), ValidationException);
}

BOOST_AUTO_TEST_CASE(CoinsViewCache_ApplyBlock_InvalidOutputMMRSize)
{
    auto pDBView = mw::CoinsViewDB::Open(m_path_root, nullptr, GetDB());
    BOOST_REQUIRE(pDBView != nullptr);

    auto pCachedView = std::make_shared<mw::CoinsViewCache>(pDBView);
    test::Miner miner(m_path_root);

    test::Tx tx = test::Tx::CreatePegIn(5'000'000);
    mw::Block::CPtr pBlock = miner.MineBlock(1, { tx }).GetBlock();

    mw::Block::CPtr pInvalidBlock = std::make_shared<mw::Block>(
        mw::MutHeader(pBlock->GetHeader())
            .SetNumOutputs(pBlock->GetHeader()->GetNumTXOs() + 1)
            .Build(),
        pBlock->GetTxBody()
    );

    BOOST_REQUIRE_THROW(pCachedView->ApplyBlock(pInvalidBlock), ValidationException);
}

BOOST_AUTO_TEST_CASE(CoinsViewCache_ApplyBlock_InvalidLeafsetRoot)
{
    auto pDBView = mw::CoinsViewDB::Open(m_path_root, nullptr, GetDB());
    BOOST_REQUIRE(pDBView != nullptr);

    auto pCachedView = std::make_shared<mw::CoinsViewCache>(pDBView);
    test::Miner miner(m_path_root);

    test::Tx tx = test::Tx::CreatePegIn(5'000'000);
    mw::Block::CPtr pBlock = miner.MineBlock(1, { tx }).GetBlock();

    mw::Block::CPtr pInvalidBlock = std::make_shared<mw::Block>(
        mw::MutHeader(pBlock->GetHeader())
            .SetLeafsetRoot(SecretKey::Random().GetBigInt())
            .Build(),
        pBlock->GetTxBody()
    );

    BOOST_REQUIRE_THROW(pCachedView->ApplyBlock(pInvalidBlock), ValidationException);
}

BOOST_AUTO_TEST_CASE(CoinsViewCache_ApplyBlock_InvalidKernelExcessSum)
{
    auto pDBView = mw::CoinsViewDB::Open(m_path_root, nullptr, GetDB());
    BOOST_REQUIRE(pDBView != nullptr);

    auto pCachedView = std::make_shared<mw::CoinsViewCache>(pDBView);
    test::Miner miner(m_path_root);

    test::Tx tx = test::Tx::CreatePegIn(5'000'000);
    mw::Block::CPtr pBlock = miner.MineBlock(1, { tx }).GetBlock();

    BlindingFactor bad_offset = pBlock->GetHeader()->GetKernelOffset();
    while (bad_offset == pBlock->GetHeader()->GetKernelOffset()) {
        bad_offset = BlindingFactor::Random();
    }

    mw::Block::CPtr pInvalidBlock = std::make_shared<mw::Block>(
        mw::MutHeader(pBlock->GetHeader())
            .SetKernelOffset(bad_offset.GetBigInt())
            .Build(),
        pBlock->GetTxBody()
    );

    BOOST_REQUIRE_THROW(pCachedView->ApplyBlock(pInvalidBlock), ValidationException);
}

BOOST_AUTO_TEST_SUITE_END()
