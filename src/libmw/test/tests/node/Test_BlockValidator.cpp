// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/node/BlockValidator.h>

#include <chain.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <mw/crypto/Schnorr.h>
#include <mw/mmr/MMR.h>
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

    CBlock extra_hogex_marker = valid;
    CMutableTransaction marked_deposit(*extra_hogex_marker.vtx[1]);
    marked_deposit.m_hogEx = true;
    extra_hogex_marker.vtx[1] = MakeTransactionRef(std::move(marked_deposit));
    BOOST_REQUIRE(extra_hogex_marker.GetHash() == valid.GetHash());

    BlockValidationState marker_state;
    BOOST_CHECK(!MWEB::Node::ContextualCheckBlock(extra_hogex_marker, consensus, &previous, marker_state));
    BOOST_CHECK(marker_state.GetResult() == BlockValidationResult::BLOCK_MUTATED);
    BOOST_CHECK_EQUAL(marker_state.GetRejectReason(), "bad-hogex-position");

    consensus.mweb_pegout_feature_activation_height = height;
    consensus.mweb_extradata_feature_activation_height = height;
    const Kernel& valid_kernel = valid_mweb->GetKernels().front();
    const auto make_noncanonical_kernel = [&](const uint8_t feature_bit) {
        const uint8_t features = valid_kernel.GetFeatures() | feature_bit;
        const boost::optional<CAmount> fee =
            (valid_kernel.GetFeatures() & Kernel::FEE_FEATURE_BIT)
                ? boost::make_optional(valid_kernel.GetFee())
                : boost::none;
        const boost::optional<CAmount> pegin_amount = valid_kernel.HasPegIn()
            ? boost::make_optional(valid_kernel.GetPegIn())
            : boost::none;
        const boost::optional<int32_t> lock_height =
            (valid_kernel.GetFeatures() & Kernel::HEIGHT_LOCK_FEATURE_BIT)
                ? boost::make_optional(valid_kernel.GetLockHeight())
                : boost::none;
        const boost::optional<PublicKey> stealth_excess = valid_kernel.HasStealthExcess()
            ? boost::make_optional(valid_kernel.GetStealthExcess())
            : boost::none;
        return Kernel(
            features,
            fee,
            pegin_amount,
            valid_kernel.GetPegOuts(),
            lock_height,
            stealth_excess,
            valid_kernel.GetExtraData(),
            valid_kernel.GetExcess(),
            valid_kernel.GetSignature()
        );
    };
    const auto check_kernel_feature = [&](const uint8_t feature_bit, const std::string& reject_reason) {
        CBlock mutated = valid;
        mutated.mweb_block = MWEB::Block{mw::MutBlock(valid_mweb)
            .SetKernels({make_noncanonical_kernel(feature_bit)})
            .Build()};
        BOOST_REQUIRE(mutated.GetHash() == valid.GetHash());

        BlockValidationState state;
        BOOST_CHECK(!MWEB::Node::ContextualCheckBlock(mutated, consensus, &previous, state));
        BOOST_CHECK(state.GetResult() == BlockValidationResult::BLOCK_MUTATED);
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-blk-mweb");

        MemMMR kernel_mmr;
        for (const Kernel& kernel : mutated.mweb_block.m_block->GetKernels()) {
            kernel_mmr.Add(kernel);
        }
        const auto committed_mweb = std::make_shared<mw::Block>(
            mw::MutHeader(mutated.mweb_block.m_block->GetHeader())
                .SetKernelRoot(kernel_mmr.Root())
                .Build(),
            mutated.mweb_block.m_block->GetTxBody());
        const CBlock committed = make_block(committed_mweb, pegin.GetKernelID());

        BlockValidationState committed_state;
        BOOST_CHECK(!MWEB::Node::ContextualCheckBlock(committed, consensus, &previous, committed_state));
        BOOST_CHECK(committed_state.GetResult() == BlockValidationResult::BLOCK_MUTATED);
        BOOST_CHECK_EQUAL(committed_state.GetRejectReason(), reject_reason);
    };
    check_kernel_feature(Kernel::PEGOUT_FEATURE_BIT, "bad-mweb-empty-pegout");
    check_kernel_feature(Kernel::EXTRA_DATA_FEATURE_BIT, "bad-mweb-empty-extradata");

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

BOOST_AUTO_TEST_CASE(ContextualCheckBlock_KernelSerializationCollisionIsMutated)
{
    auto consensus = Params().GetConsensus();
    consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;

    const int height = 3'172'640;
    consensus.mweb_pegout_feature_activation_height = height;
    consensus.mweb_extradata_feature_activation_height = height;

    constexpr CAmount pegin_amount = 6;
    constexpr CAmount output_amount = 1;
    constexpr CAmount pegout_amount = 5;
    const uint8_t features =
        Kernel::PEGIN_FEATURE_BIT |
        Kernel::PEGOUT_FEATURE_BIT |
        Kernel::HEIGHT_LOCK_FEATURE_BIT |
        Kernel::EXTRA_DATA_FEATURE_BIT;
    const boost::optional<CAmount> pegin(pegin_amount);
    const std::vector<PegOutCoin> pegouts{
        PegOutCoin(pegout_amount, CScript() << OP_TRUE)
    };
    const auto lock_height = boost::make_optional<int32_t>(0);
    const std::vector<uint8_t> extra_data{0x42};

    const BlindingFactor excess_blind = BlindingFactor::Random();
    const Commitment excess = Commitment::Blinded(excess_blind, 0);
    const Signature signature = Schnorr::Sign(
        excess_blind.data(),
        Kernel::GetSignatureMessage(
            features,
            excess,
            boost::none,
            boost::none,
            pegin,
            pegouts,
            lock_height,
            extra_data
        )
    );
    const Kernel valid_kernel(
        features,
        boost::none,
        pegin,
        pegouts,
        lock_height,
        boost::none,
        extra_data,
        excess,
        signature
    );

    const SecretKey sender_key = SecretKey::Random();
    const test::TxOutput output = test::TxOutput::Create(
        sender_key,
        SecretKey::Random(),
        SecretKey::Random(),
        output_amount
    );
    Blinds kernel_offset;
    kernel_offset.Add(output.GetBlind()).Sub(excess_blind);
    Blinds stealth_offset;
    stealth_offset.Add(sender_key);
    const auto valid_tx = mw::Transaction::Create(
        kernel_offset.Total(),
        stealth_offset.Total(),
        {},
        {output.GetOutput()},
        {valid_kernel}
    );
    BOOST_REQUIRE_NO_THROW(valid_tx->Validate());

    test::Miner miner(GetDataDir());
    const auto prior = miner.MineBlock(height - 1).GetBlock();
    const auto valid_mweb = miner.MineBlock(
        height,
        {test::Tx(valid_tx, {output})}
    ).GetBlock();

    CBlockIndex previous;
    previous.nHeight = height - 1;
    previous.hogex_hash = uint256S("01");
    previous.mweb_header = prior->GetHeader();
    previous.mweb_amount = 100;

    const auto make_block = [&](const mw::Block::CPtr& body) {
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        coinbase.vout.emplace_back(0, CScript() << OP_TRUE);

        CMutableTransaction deposit;
        deposit.vin.emplace_back(uint256S("02"), 0);
        deposit.vout.emplace_back(pegin_amount, GetScriptForPegin(valid_kernel.GetKernelID()));

        CMutableTransaction hogex;
        hogex.m_hogEx = true;
        hogex.vin.emplace_back(previous.hogex_hash, 0);
        hogex.vin.emplace_back(deposit.GetHash(), 0);
        hogex.vout.emplace_back(
            previous.mweb_amount + output_amount,
            CScript() << OP_8 << body->GetHash().vec()
        );
        hogex.vout.emplace_back(pegout_amount, CScript() << OP_TRUE);

        CBlock block;
        block.vtx = {
            MakeTransactionRef(coinbase),
            MakeTransactionRef(deposit),
            MakeTransactionRef(hogex)
        };
        block.hashMerkleRoot = BlockMerkleRoot(block);
        block.mweb_block = MWEB::Block{body};
        return block;
    };

    const CBlock valid_block = make_block(valid_mweb);
    BlockValidationState valid_state;
    BOOST_REQUIRE(MWEB::Node::ContextualCheckBlock(valid_block, consensus, &previous, valid_state));

    auto collision_bytes = valid_kernel.Serialized();
    BOOST_REQUIRE(collision_bytes.size() >= 2);
    BOOST_REQUIRE_EQUAL(collision_bytes[0], features);
    BOOST_REQUIRE_EQUAL(collision_bytes[1], pegin_amount);
    collision_bytes.insert(collision_bytes.begin() + 2, 0x00);
    const Kernel collision_kernel = Kernel::Deserialize(collision_bytes);

    BOOST_REQUIRE(collision_kernel.GetPegOuts().empty());
    BOOST_REQUIRE_EQUAL(collision_kernel.GetLockHeight(), 1);
    BOOST_REQUIRE(collision_kernel.GetExtraData() == std::vector<uint8_t>({0x01, 0x51, 0x00, 0x01, 0x42}));
    BOOST_REQUIRE(collision_kernel.Serialized() == valid_kernel.Serialized());
    BOOST_REQUIRE(collision_kernel.GetKernelID() == valid_kernel.GetKernelID());

    const auto collision_mweb = mw::MutBlock(valid_mweb)
        .SetKernels({collision_kernel})
        .Build();
    BOOST_REQUIRE(collision_mweb->GetHash() == valid_mweb->GetHash());
    BOOST_REQUIRE(collision_mweb->HasValidKernelMMR());

    CBlock collision_block = valid_block;
    collision_block.mweb_block = MWEB::Block{collision_mweb};
    BOOST_REQUIRE(collision_block.GetHash() == valid_block.GetHash());

    BlockValidationState collision_state;
    BOOST_CHECK(!MWEB::Node::ContextualCheckBlock(collision_block, consensus, &previous, collision_state));
    BOOST_CHECK(collision_state.GetResult() == BlockValidationResult::BLOCK_MUTATED);
    BOOST_CHECK_EQUAL(collision_state.GetRejectReason(), "bad-mweb-empty-pegout");

    BlockValidationState replacement_state;
    BOOST_CHECK(MWEB::Node::ContextualCheckBlock(valid_block, consensus, &previous, replacement_state));
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
