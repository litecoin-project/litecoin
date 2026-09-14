// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/node/CoinsView.h>
#include <mw/exceptions/ValidationException.h>
#include <mw/models/tx/MutableTx.h>
#include <memusage.h>

#include <test_framework/Miner.h>
#include <test_framework/TestMWEB.h>
#include <test_framework/TxBuilder.h>

using namespace mw;

BOOST_FIXTURE_TEST_SUITE(TestCoinsView, MWEBTestingSetup)

// Coin accounting includes optional fields, extra data, and proof capacity, and retains spent coins until their actions are flushed.
BOOST_AUTO_TEST_CASE(CoinsViewCache_MemoryUsage_Payloads)
{
    auto base = mw::CoinsViewDB::Open(m_path_root, nullptr, GetDB());
    mw::CoinsViewCache plain(base);
    mw::CoinsViewCache padded(base);
    const auto tx = test::Tx::CreatePegIn(5'000'000);
    const auto& output = tx.GetOutputs().front().GetOutput();
    plain.AddCoin(1, output);

    auto proof_bytes = output.GetRangeProof()->vec();
    proof_bytes.reserve(2048);
    const auto proof = std::make_shared<RangeProof>(std::move(proof_bytes));
    std::vector<uint8_t> extra_data(1024, 0x42);
    extra_data.reserve(4096); // The cached coin copies the data, so its capacity may differ.
    const auto& message = output.GetOutputMessage();
    const mw::Output padded_output{output.GetCommitment(), output.GetSenderPubKey(), output.GetReceiverPubKey(),
        mw::OutputMessage{uint8_t(message.features | mw::OutputMessage::EXTRA_DATA_FEATURE_BIT),
            message.standard_fields, std::move(extra_data)}, proof, output.GetSignature()};
    padded.AddCoin(1, padded_output);
    const auto coin = padded.GetCoin(padded_output.GetOutputID());
    BOOST_REQUIRE(coin);
    const size_t extra_usage = memusage::DynamicUsage(coin->GetOutput().GetExtraData()) +
        memusage::DynamicUsage(proof->vec()) - memusage::DynamicUsage(output.GetRangeProof()->vec());
    BOOST_CHECK_EQUAL(padded.DynamicMemoryUsage() - plain.DynamicMemoryUsage(), extra_usage);

    mw::CoinsViewCache without_standard_fields(base);
    const mw::Output nonstandard_output{output.GetCommitment(), output.GetSenderPubKey(), output.GetReceiverPubKey(),
        mw::OutputMessage{mw::OutputMessage::EXTRA_DATA_FEATURE_BIT, std::nullopt, padded_output.GetExtraData()},
        proof, output.GetSignature()};
    without_standard_fields.AddCoin(1, nonstandard_output);
    BOOST_REQUIRE(message.standard_fields);
    const size_t standard_usage = memusage::DynamicUsage(message.standard_fields->key_exchange_pubkey.vec()) +
        memusage::DynamicUsage(message.standard_fields->masked_nonce.vec());
    BOOST_CHECK_EQUAL(padded.DynamicMemoryUsage() - without_standard_fields.DynamicMemoryUsage(), standard_usage);

    const size_t added_usage = padded.DynamicMemoryUsage();
    padded.SpendCoin(padded_output.GetOutputID());
    BOOST_CHECK_GT(padded.DynamicMemoryUsage(), added_usage);
    BOOST_CHECK(!padded.GetCoin(padded_output.GetOutputID()));
    padded.AddCoin(2, padded_output);
    BOOST_CHECK_GT(padded.DynamicMemoryUsage(), added_usage + sizeof(mw::Coin) + extra_usage);
    BOOST_REQUIRE(padded.GetCoin(padded_output.GetOutputID()));
    BOOST_CHECK_EQUAL(padded.GetCoin(padded_output.GetOutputID())->GetBlockHeight(), 2);
}

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

BOOST_AUTO_TEST_CASE(CoinsViewCache_ApplyBlock_RejectedBlockDoesNotMutateCache)
{
    auto pDBView = mw::CoinsViewDB::Open(m_path_root, nullptr, GetDB());
    BOOST_REQUIRE(pDBView != nullptr);

    auto pCachedView = std::make_shared<mw::CoinsViewCache>(pDBView);
    test::Miner miner(m_path_root);

    test::Tx funding_tx = test::Tx::CreatePegIn(5'000'000);
    mw::Block::CPtr pBlock1 = miner.MineBlock(1, { funding_tx }).GetBlock();
    pCachedView->ApplyBlock(pBlock1);

    const mw::Header::CPtr best_header_before = pCachedView->GetBestHeader();
    const mw::Hash output_root_before = pCachedView->GetOutputPMMR()->Root();
    const uint64_t num_txos_before = pCachedView->GetOutputPMMR()->GetNumLeaves();
    const mw::Hash leafset_root_before = pCachedView->GetLeafSet()->Root();

    test::Tx next_tx = test::Tx::CreatePegIn(2'000'000);
    mw::Block::CPtr pBlock2 = miner.MineBlock(2, { next_tx }).GetBlock();
    mw::Block::CPtr pInvalidBlock = std::make_shared<mw::Block>(
        mw::MutHeader(pBlock2->GetHeader())
            .SetOutputRoot(SecretKey::Random().GetBigInt())
            .Build(),
        pBlock2->GetTxBody()
    );

    BOOST_REQUIRE_THROW(pCachedView->ApplyBlock(pInvalidBlock), ValidationException);
    BOOST_REQUIRE(pCachedView->GetBestHeader() != nullptr);
    BOOST_CHECK(pCachedView->GetBestHeader()->GetHash() == best_header_before->GetHash());
    BOOST_CHECK(pCachedView->GetOutputPMMR()->Root() == output_root_before);
    BOOST_CHECK_EQUAL(pCachedView->GetOutputPMMR()->GetNumLeaves(), num_txos_before);
    BOOST_CHECK(pCachedView->GetLeafSet()->Root() == leafset_root_before);
    BOOST_CHECK(pCachedView->GetCoin(funding_tx.GetOutputs().front().GetOutputID()) != nullptr);
    BOOST_CHECK(pCachedView->GetCoin(next_tx.GetOutputs().front().GetOutputID()) == nullptr);
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
