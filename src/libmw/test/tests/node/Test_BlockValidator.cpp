// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/node/BlockValidator.h>
#include <mw/consensus/Weight.h>
#include <mw/crypto/Schnorr.h>
#include <mw/models/tx/MutableTx.h>

#include <test_framework/Miner.h>
#include <test_framework/TestMWEB.h>
#include <test_framework/TxBuilder.h>

using namespace mw;

BOOST_FIXTURE_TEST_SUITE(TestBlockValidator, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(BlockValidator_Test_ValidBlock)
{
    test::Miner miner(m_path_root);

    // Block 1 - 1 pegin & 1 pegout
    test::Tx pegin_tx = test::Tx::CreatePegIn(5'000'000);
    test::Tx pegout_tx = test::Tx::CreatePegOut(pegin_tx.GetOutputs().front());
    mw::Block::CPtr pBlock = miner.MineBlock(1, { pegin_tx, pegout_tx }).GetBlock();

    bool is_valid = BlockValidator::ValidateBlock(
        pBlock,
        std::vector<PegInCoin>{pegin_tx.GetPegInCoin()},
        std::vector<PegOutCoin>{pegout_tx.GetPegOutCoin()}
    );
    BOOST_CHECK(is_valid);

    // Block 2 - Empty
    mw::Block::CPtr pEmptyBlock = miner.MineBlock(2).GetBlock();

    is_valid = BlockValidator::ValidateBlock(
        pEmptyBlock,
        std::vector<PegInCoin>{},
        std::vector<PegOutCoin>{}
    );
    BOOST_CHECK(is_valid);
}

BOOST_AUTO_TEST_CASE(BlockValidator_Test_PeginMismatch)
{
    test::Miner miner(m_path_root);

    {
        test::Tx pegin_tx = test::Tx::CreatePegIn(5'000'000);
        mw::Block::CPtr pBlock = miner.MineBlock(1, {pegin_tx}).GetBlock();

        bool is_valid = BlockValidator::ValidateBlock(
            pBlock,
            std::vector<PegInCoin>{},
            std::vector<PegOutCoin>{}
        );
        BOOST_CHECK(!is_valid);
    }

    {
        test::Tx pegin_tx = test::Tx::CreatePegIn(5'000'000);
        mw::Block::CPtr pBlock = miner.MineBlock(2, {}).GetBlock();

        bool is_valid = BlockValidator::ValidateBlock(
            pBlock,
            std::vector<PegInCoin>{pegin_tx.GetPegInCoin()},
            std::vector<PegOutCoin>{}
        );
        BOOST_CHECK(!is_valid);
    }

    {
        test::Tx pegin_tx = test::Tx::CreatePegIn(5'000'000);
        mw::Block::CPtr pBlock = miner.MineBlock(3, {pegin_tx}).GetBlock();
        PegInCoin pegin_coin = pegin_tx.GetPegInCoin();

        bool is_valid = BlockValidator::ValidateBlock(
            pBlock,
            std::vector<PegInCoin>{
                pegin_coin,
                pegin_coin,
            },
            std::vector<PegOutCoin>{}
        );
        BOOST_CHECK(!is_valid);

        is_valid = BlockValidator::ValidateBlock(
            pBlock,
            std::vector<PegInCoin>{
                pegin_coin,
                PegInCoin{0, pegin_coin.GetKernelID()},
            },
            std::vector<PegOutCoin>{}
        );
        BOOST_CHECK(!is_valid);
    }
}

BOOST_AUTO_TEST_CASE(BlockValidator_Test_PegoutMismatch)
{
    test::Miner miner(m_path_root);

    {
        test::Tx pegin_tx = test::Tx::CreatePegIn(5'000'000);
        test::Tx pegout_tx = test::Tx::CreatePegOut(pegin_tx.GetOutputs().front());
        mw::Block::CPtr pBlock = miner.MineBlock(1, {pegin_tx, pegout_tx}).GetBlock();

        bool is_valid = BlockValidator::ValidateBlock(
            pBlock,
            std::vector<PegInCoin>{pegin_tx.GetPegInCoin()},
            std::vector<PegOutCoin>{}
        );
        BOOST_CHECK(!is_valid);
    }
    
    {
        test::Tx pegin_tx = test::Tx::CreatePegIn(5'000'000);
        test::Tx pegout_tx = test::Tx::CreatePegOut(pegin_tx.GetOutputs().front());
        mw::Block::CPtr pBlock = miner.MineBlock(1, {pegin_tx}).GetBlock();

        bool is_valid = BlockValidator::ValidateBlock(
            pBlock,
            std::vector<PegInCoin>{pegin_tx.GetPegInCoin()},
            std::vector<PegOutCoin>{pegout_tx.GetPegOutCoin()}
        );
        BOOST_CHECK(!is_valid);
    }
}

BOOST_AUTO_TEST_CASE(BlockValidator_Test_KernelMismatch)
{
    test::Miner miner(m_path_root);

    test::Tx pegin_tx = test::Tx::CreatePegIn(5'000'000);
    mw::Block::CPtr pBlock = miner.MineBlock(1, { pegin_tx }).GetBlock();

    bool is_valid = BlockValidator::ValidateBlock(
        pBlock,
        std::vector<PegInCoin>{pegin_tx.GetPegInCoin()},
        std::vector<PegOutCoin>{}
    );
    BOOST_CHECK(is_valid);
    
    // Kernel root mismatch
    mw::Block::CPtr pBlockKernelRootMismatch = std::make_shared<mw::Block>(
        mw::MutHeader(pBlock->GetHeader())
            .SetKernelRoot(SecretKey::Random().GetBigInt())
            .Build(),
        pBlock->GetTxBody()
    );

    is_valid = BlockValidator::ValidateBlock(
        pBlockKernelRootMismatch,
        std::vector<PegInCoin>{pegin_tx.GetPegInCoin()},
        std::vector<PegOutCoin>{}
    );
    BOOST_CHECK(!is_valid);

    
    // Num kernels mismatch
    mw::Block::CPtr pBlockNumKernelsMismatch = std::make_shared<mw::Block>(
        mw::MutHeader(pBlock->GetHeader())
            .SetNumKernels(10)
            .Build(),
        pBlock->GetTxBody()
    );

    is_valid = BlockValidator::ValidateBlock(
        pBlockNumKernelsMismatch,
        std::vector<PegInCoin>{pegin_tx.GetPegInCoin()},
        std::vector<PegOutCoin>{}
    );
    BOOST_CHECK(!is_valid);
}

BOOST_AUTO_TEST_CASE(BlockValidator_Test_InvalidStealthExcess)
{
    test::Miner miner(m_path_root);

    test::Tx pegin_tx = test::Tx::CreatePegIn(5'000'000);
    mw::Block::CPtr pBlock = miner.MineBlock(1, {pegin_tx}).GetBlock();

    bool is_valid = BlockValidator::ValidateBlock(
        pBlock,
        std::vector<PegInCoin>{pegin_tx.GetPegInCoin()},
        std::vector<PegOutCoin>{});
    BOOST_CHECK(is_valid);

    // Stealth excess invalid
    mw::Block::CPtr pBlockKernelRootMismatch = std::make_shared<mw::Block>(
        mw::MutHeader(pBlock->GetHeader())
            .SetStealthOffset(SecretKey::Random().GetBigInt())
            .Build(),
        pBlock->GetTxBody()
    );

    is_valid = BlockValidator::ValidateBlock(
        pBlockKernelRootMismatch,
        std::vector<PegInCoin>{pegin_tx.GetPegInCoin()},
        std::vector<PegOutCoin>{}
    );
    BOOST_CHECK(!is_valid);
}

BOOST_AUTO_TEST_CASE(BlockValidator_Test_OutputSorting)
{
    test::Miner miner(m_path_root);

    test::Tx tx = test::TxBuilder()
        .AddPeginKernel(5'000'000)
        .AddOutput(3'000'000, SecretKey::Random(), StealthAddress::Random())
        .AddOutput(2'000'000, SecretKey::Random(), StealthAddress::Random())
        .Build();
    mw::Block::CPtr pBlock = miner.MineBlock(1, {tx}).GetBlock();

    bool is_valid = BlockValidator::ValidateBlock(
        pBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(is_valid);

    // Swap outputs so they're no longer in order
    std::vector<mw::Output> outputs = pBlock->GetOutputs();
    mw::Output tmp = outputs[0];
    outputs[0] = outputs[1];
    outputs[1] = tmp;

    BOOST_REQUIRE(outputs[0].GetOutputID() > outputs[1].GetOutputID());
    mw::Block::CPtr pUnsortedBlock = mw::MutBlock(pBlock)
        .SetOutputs(std::move(outputs))
        .Build();

    is_valid = BlockValidator::ValidateBlock(
        pUnsortedBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(!is_valid);
}

BOOST_AUTO_TEST_CASE(BlockValidator_Test_InputSorting)
{
    test::Miner miner(m_path_root);

    test::Tx funding_tx = test::TxBuilder()
        .AddPeginKernel(10'000'000)
        .AddOutput(4'000'000, SecretKey::Random(), StealthAddress::Random())
        .AddOutput(6'000'000, SecretKey::Random(), StealthAddress::Random())
        .Build();
    miner.MineBlock(1, {funding_tx});

    test::Tx tx = test::TxBuilder()
        .AddInput(funding_tx.GetOutputs()[0])
        .AddInput(funding_tx.GetOutputs()[1])
        .AddOutput(10'000'000, SecretKey::Random(), StealthAddress::Random())
        .AddPlainKernel(0)
        .Build();
    mw::Block::CPtr pBlock = miner.MineBlock(2, {tx}).GetBlock();

    bool is_valid = BlockValidator::ValidateBlock(
        pBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(is_valid);

    // Swap inputs so they're no longer in order
    std::vector<mw::Input> inputs = pBlock->GetInputs();
    mw::Input tmp = inputs[0];
    inputs[0] = inputs[1];
    inputs[1] = tmp;

    BOOST_REQUIRE(inputs[0].GetOutputID() > inputs[1].GetOutputID());
    mw::Block::CPtr pUnsortedBlock = mw::MutBlock(pBlock)
        .SetInputs(std::move(inputs))
        .Build();

    is_valid = BlockValidator::ValidateBlock(
        pUnsortedBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(!is_valid);
}

BOOST_AUTO_TEST_CASE(BlockValidator_Test_KernelSorting)
{
    test::Miner miner(m_path_root);

    test::Tx tx = test::TxBuilder()
        .AddPeginKernel(5'000'000)
        .AddPeginKernel(10'000'000)
        .AddOutput(15'000'000, SecretKey::Random(), StealthAddress::Random())
        .Build();
    mw::Block::CPtr pBlock = miner.MineBlock(1, {tx}).GetBlock();

    bool is_valid = BlockValidator::ValidateBlock(
        pBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(is_valid);

    // Swap kernels so they're no longer in order
    std::vector<mw::Kernel> kernels = pBlock->GetKernels();
    mw::Kernel tmp = kernels[0];
    kernels[0] = kernels[1];
    kernels[1] = tmp;

    const auto first_supply_change = kernels[0].GetSupplyChange();
    const auto second_supply_change = kernels[1].GetSupplyChange();
    BOOST_REQUIRE(first_supply_change.has_value());
    BOOST_REQUIRE(second_supply_change.has_value());
    BOOST_REQUIRE(*first_supply_change < *second_supply_change);
    mw::Block::CPtr pUnsortedBlock = mw::MutBlock(pBlock)
        .SetKernels(std::move(kernels))
        .Build();

    is_valid = BlockValidator::ValidateBlock(
        pUnsortedBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(!is_valid);
}

BOOST_AUTO_TEST_CASE(BlockValidator_Test_BlockWeight)
{
    test::Miner miner(m_path_root);

    test::Tx tx = test::TxBuilder()
        .AddPeginKernel(5'000'000)
        .AddOutput(5'000'000, SecretKey::Random(), StealthAddress::Random())
        .Build();
    mw::Block::CPtr pBlock = miner.MineBlock(1, {tx}).GetBlock();

    bool is_valid = BlockValidator::ValidateBlock(
        pBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(is_valid);

    std::vector<mw::Output> outputs = pBlock->GetOutputs();
    const mw::Output& output = outputs.front();
    const size_t current_weight = Weight::Calculate(pBlock->GetTxBody());
    const size_t output_weight = Weight::CalcOutputWeight(output.HasStandardFields(), output.GetExtraData());
    const size_t additional_outputs = ((mw::MAX_BLOCK_WEIGHT - current_weight) / output_weight) + 1;
    outputs.insert(outputs.end(), additional_outputs, output);

    BOOST_REQUIRE(Weight::ExceedsMaximum(mw::TxBody(pBlock->GetInputs(), outputs, pBlock->GetKernels())));

    mw::Block::CPtr pHeavyBlock = mw::MutBlock(pBlock)
        .SetOutputs(std::move(outputs))
        .Build();

    is_valid = BlockValidator::ValidateBlock(
        pHeavyBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(!is_valid);
}

BOOST_AUTO_TEST_CASE(BlockValidator_Test_DuplicateSpentIDs)
{
    test::Miner miner(m_path_root);

    test::Tx funding_tx = test::TxBuilder()
        .AddPeginKernel(5'000'000)
        .AddOutput(5'000'000, SecretKey::Random(), StealthAddress::Random())
        .Build();
    miner.MineBlock(1, {funding_tx});

    test::Tx tx = test::TxBuilder()
        .AddInput(funding_tx.GetOutputs()[0])
        .AddOutput(5'000'000, SecretKey::Random(), StealthAddress::Random())
        .AddPlainKernel(0)
        .Build();
    mw::Block::CPtr pBlock = miner.MineBlock(2, {tx}).GetBlock();

    bool is_valid = BlockValidator::ValidateBlock(
        pBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(is_valid);

    std::vector<mw::Input> inputs = pBlock->GetInputs();
    inputs.push_back(inputs.front());

    mw::Block::CPtr pDuplicateBlock = mw::MutBlock(pBlock)
        .SetInputs(std::move(inputs))
        .Build();

    is_valid = BlockValidator::ValidateBlock(
        pDuplicateBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(!is_valid);
}

BOOST_AUTO_TEST_CASE(BlockValidator_Test_DuplicateOutputIDs)
{
    test::Miner miner(m_path_root);

    test::Tx tx = test::TxBuilder()
        .AddPeginKernel(5'000'000)
        .AddOutput(5'000'000, SecretKey::Random(), StealthAddress::Random())
        .Build();
    mw::Block::CPtr pBlock = miner.MineBlock(1, {tx}).GetBlock();

    bool is_valid = BlockValidator::ValidateBlock(
        pBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(is_valid);

    std::vector<mw::Output> outputs = pBlock->GetOutputs();
    outputs.push_back(outputs.front());

    mw::Block::CPtr pDuplicateBlock = mw::MutBlock(pBlock)
        .SetOutputs(std::move(outputs))
        .Build();

    is_valid = BlockValidator::ValidateBlock(
        pDuplicateBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(!is_valid);
}

BOOST_AUTO_TEST_CASE(BlockValidator_Test_DuplicateKernelIDs)
{
    test::Miner miner(m_path_root);

    test::Tx tx = test::TxBuilder()
        .AddPeginKernel(5'000'000)
        .AddOutput(5'000'000, SecretKey::Random(), StealthAddress::Random())
        .Build();
    mw::Block::CPtr pBlock = miner.MineBlock(1, {tx}).GetBlock();

    bool is_valid = BlockValidator::ValidateBlock(
        pBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(is_valid);

    std::vector<mw::Kernel> kernels = pBlock->GetKernels();
    kernels.push_back(kernels.front());

    mw::Block::CPtr pDuplicateBlock = std::make_shared<mw::Block>(
        mw::MutHeader(pBlock->GetHeader())
            .SetNumKernels(kernels.size())
            .Build(),
        mw::TxBody(pBlock->GetInputs(), pBlock->GetOutputs(), kernels)
    );

    is_valid = BlockValidator::ValidateBlock(
        pDuplicateBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(!is_valid);
}

BOOST_AUTO_TEST_CASE(BlockValidator_Test_InvalidInputSignature)
{
    test::Miner miner(m_path_root);

    test::Tx funding_tx = test::TxBuilder()
        .AddPeginKernel(5'000'000)
        .AddOutput(5'000'000, SecretKey::Random(), StealthAddress::Random())
        .Build();
    miner.MineBlock(1, {funding_tx});

    test::Tx tx = test::TxBuilder()
        .AddInput(funding_tx.GetOutputs()[0])
        .AddOutput(5'000'000, SecretKey::Random(), StealthAddress::Random())
        .AddPlainKernel(0)
        .Build();
    mw::Block::CPtr pBlock = miner.MineBlock(2, {tx}).GetBlock();

    bool is_valid = BlockValidator::ValidateBlock(
        pBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(is_valid);

    mw::MutableTx mutable_tx = mw::MutableTx::From(*tx.GetTransaction());
    mutable_tx.inputs.front().signature = Signature(RandomBigInt<Signature::SIZE>());
    mw::Transaction::CPtr pInvalidTx = mutable_tx.Finalized().value();

    mw::Block::CPtr pInvalidSigBlock = mw::MutBlock(pBlock)
        .SetInputs(pInvalidTx->GetInputs())
        .SetOutputs(pInvalidTx->GetOutputs())
        .SetKernels(pInvalidTx->GetKernels())
        .Build();

    is_valid = BlockValidator::ValidateBlock(
        pInvalidSigBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(!is_valid);
}

BOOST_AUTO_TEST_CASE(BlockValidator_Test_InvalidOutputSignature)
{
    test::Miner miner(m_path_root);

    test::Tx tx = test::TxBuilder()
        .AddPeginKernel(5'000'000)
        .AddOutput(5'000'000, SecretKey::Random(), StealthAddress::Random())
        .Build();
    mw::Block::CPtr pBlock = miner.MineBlock(1, {tx}).GetBlock();

    bool is_valid = BlockValidator::ValidateBlock(
        pBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(is_valid);

    mw::MutableTx mutable_tx = mw::MutableTx::From(*tx.GetTransaction());
    mutable_tx.outputs.front().signature = Signature(RandomBigInt<Signature::SIZE>());
    mw::Transaction::CPtr pInvalidTx = mutable_tx.Finalized().value();

    mw::Block::CPtr pInvalidSigBlock = mw::MutBlock(pBlock)
        .SetInputs(pInvalidTx->GetInputs())
        .SetOutputs(pInvalidTx->GetOutputs())
        .SetKernels(pInvalidTx->GetKernels())
        .Build();

    is_valid = BlockValidator::ValidateBlock(
        pInvalidSigBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(!is_valid);
}

BOOST_AUTO_TEST_CASE(BlockValidator_Test_InvalidKernelSignature)
{
    test::Miner miner(m_path_root);

    test::Tx funding_tx = test::TxBuilder()
        .AddPeginKernel(5'000'000)
        .AddOutput(5'000'000, SecretKey::Random(), StealthAddress::Random())
        .Build();
    miner.MineBlock(1, {funding_tx});

    test::Tx tx = test::TxBuilder()
        .AddInput(funding_tx.GetOutputs()[0])
        .AddOutput(5'000'000, SecretKey::Random(), StealthAddress::Random())
        .AddPlainKernel(0)
        .Build();
    mw::Block::CPtr pBlock = miner.MineBlock(2, {tx}).GetBlock();

    bool is_valid = BlockValidator::ValidateBlock(
        pBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(is_valid);

    mw::MutableTx mutable_tx = mw::MutableTx::From(*tx.GetTransaction());
    mutable_tx.kernels.front().signature = Signature(RandomBigInt<Signature::SIZE>());
    mw::Transaction::CPtr pInvalidTx = mutable_tx.Finalized().value();

    mw::Block::CPtr pInvalidSigBlock = mw::MutBlock(pBlock)
        .SetInputs(pInvalidTx->GetInputs())
        .SetOutputs(pInvalidTx->GetOutputs())
        .SetKernels(pInvalidTx->GetKernels())
        .Build();

    is_valid = BlockValidator::ValidateBlock(
        pInvalidSigBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(!is_valid);
}

BOOST_AUTO_TEST_CASE(BlockValidator_Test_InvalidRangeProof)
{
    test::Miner miner(m_path_root);

    SecretKey sender_key = SecretKey::Random();
    test::Tx tx = test::TxBuilder()
        .AddPeginKernel(5'000'000)
        .AddOutput(5'000'000, sender_key, StealthAddress::Random())
        .Build();
    mw::Block::CPtr pBlock = miner.MineBlock(1, {tx}).GetBlock();

    bool is_valid = BlockValidator::ValidateBlock(
        pBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(is_valid);

    mw::MutableTx mutable_tx = mw::MutableTx::From(*tx.GetTransaction());
    std::vector<uint8_t> proof_bytes(RangeProof::SIZE, 0);
    mutable_tx.outputs.front().proof = std::make_shared<RangeProof>(std::move(proof_bytes));

    mw::Output resigned_output(
        *mutable_tx.outputs.front().commitment,
        *mutable_tx.outputs.front().sender_pubkey,
        *mutable_tx.outputs.front().receiver_pubkey,
        *mutable_tx.outputs.front().message,
        *mutable_tx.outputs.front().proof,
        Signature()
    );
    mutable_tx.outputs.front().signature = Schnorr::Sign(sender_key.data(), resigned_output.BuildSignedMsg().GetMsgHash());

    mw::Transaction::CPtr pInvalidTx = mutable_tx.Finalized().value();
    mw::Block::CPtr pInvalidProofBlock = mw::MutBlock(pBlock)
        .SetInputs(pInvalidTx->GetInputs())
        .SetOutputs(pInvalidTx->GetOutputs())
        .SetKernels(pInvalidTx->GetKernels())
        .Build();

    is_valid = BlockValidator::ValidateBlock(
        pInvalidProofBlock,
        tx.GetPegIns(),
        tx.GetPegOuts()
    );
    BOOST_CHECK(!is_valid);
}

BOOST_AUTO_TEST_SUITE_END()
