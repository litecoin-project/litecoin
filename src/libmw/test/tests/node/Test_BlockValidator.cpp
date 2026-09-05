// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/node/BlockValidator.h>

#include <chain.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <mweb/mweb_node.h>
#include <primitives/block.h>
#include <script/standard.h>
#include <undo.h>

#include <test_framework/Miner.h>
#include <test_framework/TestMWEB.h>
#include <test_framework/TxBuilder.h>

BOOST_FIXTURE_TEST_SUITE(TestBlockValidator, MWEBTestingSetup)

// MW: TODO - Write tests for invalid blocks:
// - Pegin mismatch
// - Pegout mismatch
// - Num kernels mismatch
// - Kernel root mismatch
// - Invalid stealth excess sum
// * Block weight
// * Unsorted inputs
// - Unsorted outputs
// - Unsorted kernels
// * Duplicate spent IDs
// * Duplicate output IDs
// * Duplicate kernel IDs
// * Invalid input signature
// * Invalid output signature
// * Invalid kernel signature
// * Invalid rangeproof

BOOST_AUTO_TEST_CASE(BlockValidator_Test_ValidBlock)
{
    test::Miner miner(GetDataDir());

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

BOOST_AUTO_TEST_CASE(ConnectBlock_RevalidatesDiskBody)
{
    auto consensus = Params().GetConsensus();
    consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;

    // Exercise revalidation before the new mainnet feature activation height.
    const int height = 3'172'639;
    test::Miner miner(GetDataDir());
    const auto prior_tx = test::Tx::CreatePegIn(10'000);
    const auto prior = miner.MineBlock(height - 1, {prior_tx}).GetBlock();
    const auto pegin_tx = test::Tx::CreatePegIn(1'000);
    const auto valid_mweb = miner.MineBlock(height, {pegin_tx}).GetBlock();
    const auto pegin = pegin_tx.GetPegInCoin();
    const auto output_id = valid_mweb->GetOutputs().front().GetOutputID();

    auto db_view = mw::CoinsViewDB::Open(GetDataDir(), nullptr, GetDB());
    auto prior_view = std::make_shared<mw::CoinsViewCache>(db_view);
    prior_view->ApplyBlock(prior, false);

    CBlockIndex previous;
    previous.nHeight = height - 1;
    previous.hogex_hash = uint256S("01");
    previous.mweb_header = prior->GetHeader();
    previous.mweb_amount = 10'000;

    const auto make_block = [&](const mw::Block::CPtr& body, const mw::Hash& pegin_id) {
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        coinbase.vout.emplace_back(0, CScript() << OP_TRUE);

        CMutableTransaction deposit;
        deposit.vin.emplace_back(uint256S("02"), 0);
        deposit.vout.emplace_back(pegin.GetAmount(), GetScriptForPegin(pegin_id));

        CMutableTransaction hogex;
        hogex.m_hogEx = true;
        hogex.vin.emplace_back(previous.hogex_hash, 0);
        hogex.vin.emplace_back(deposit.GetHash(), 0);
        hogex.vout.emplace_back(previous.mweb_amount + pegin.GetAmount(), CScript() << OP_8 << body->GetHash().vec());

        CBlock block;
        block.vtx = {MakeTransactionRef(coinbase), MakeTransactionRef(deposit), MakeTransactionRef(hogex)};
        block.hashMerkleRoot = BlockMerkleRoot(block);
        block.mweb_block = MWEB::Block{body};
        return block;
    };

    const CBlock valid = make_block(valid_mweb, pegin.GetKernelID());
    BlockValidationState accepted;
    BOOST_REQUIRE(MWEB::Node::ContextualCheckBlock(valid, consensus, &previous, accepted));

    const auto check_connection = [&](const CBlock& block, const bool expected_valid) {
        // A disk reload must not inherit acceptance of an earlier body.
        CDataStream disk(SER_DISK, PROTOCOL_VERSION);
        disk << block;
        CBlock reloaded;
        disk >> reloaded;
        BOOST_REQUIRE(disk.empty());

        mw::CoinsViewCache view(prior_view);
        CBlockUndo undo;
        BlockValidationState state;
        BOOST_CHECK_EQUAL(MWEB::Node::ConnectBlock(reloaded, consensus, &previous, undo, view, state), expected_valid);
        if (expected_valid) {
            BOOST_CHECK(view.GetUTXO(output_id) != nullptr);
            BOOST_CHECK(view.GetBestHeader() == reloaded.mweb_block.GetMWEBHeader());
        } else {
            BOOST_CHECK(state.GetResult() == BlockValidationResult::BLOCK_MUTATED);
            BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-blk-mweb");
            BOOST_CHECK(view.GetUTXO(output_id) == nullptr);
            BOOST_CHECK(view.GetBestHeader() == prior->GetHeader());
        }
    };

    auto kernels = valid_mweb->GetKernels();
    auto serialized_kernel = kernels.front().Serialized();
    serialized_kernel.back() ^= 1;
    kernels.front() = Kernel::Deserialize(serialized_kernel);
    CBlock invalid_signature = valid;
    invalid_signature.mweb_block = MWEB::Block{mw::MutBlock(valid_mweb).SetKernels(kernels).Build()};
    BOOST_REQUIRE(invalid_signature.GetHash() == valid.GetHash());
    check_connection(invalid_signature, false);

    const auto invalid_root = std::make_shared<mw::Block>(
        mw::MutHeader(valid_mweb->GetHeader()).SetKernelRoot(mw::Hash{}).Build(),
        valid_mweb->GetTxBody());
    check_connection(make_block(invalid_root, pegin.GetKernelID()), false);
    check_connection(make_block(valid_mweb, mw::Hash{}), false);
    check_connection(valid, true);
}

BOOST_AUTO_TEST_CASE(BlockValidator_Test_PeginMismatch)
{
    test::Miner miner(GetDataDir());

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
    test::Miner miner(GetDataDir());

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
    test::Miner miner(GetDataDir());

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
    test::Miner miner(GetDataDir());

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
    test::Miner miner(GetDataDir());

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
    std::vector<Output> outputs = pBlock->GetOutputs();
    Output tmp = outputs[0];
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

BOOST_AUTO_TEST_CASE(BlockValidator_Test_KernelSorting)
{
    test::Miner miner(GetDataDir());

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
    std::vector<Kernel> kernels = pBlock->GetKernels();
    Kernel tmp = kernels[0];
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

BOOST_AUTO_TEST_SUITE_END()
