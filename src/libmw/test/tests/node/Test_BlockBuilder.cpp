// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/consensus/Params.h>
#include <mw/crypto/Blinds.h>
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

    test::Tx builder_tx2 = test::Tx::CreatePegOut(block1_tx1.GetOutputs().front());
    BOOST_REQUIRE(block_builder->AddTransaction(builder_tx2.GetTransaction(), {}));

    // Reject aggregate input counts above the consensus limit before
    // validating the otherwise-placeholder inputs.
    std::vector<Input> inputs(mw::MAX_NUM_INPUTS);
    const auto oversized_tx = mw::Transaction::Create({}, {}, std::move(inputs), {}, {});
    BOOST_CHECK(!block_builder->AddTransaction(oversized_tx, {}));
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

namespace {

test::Tx CreatePegInWithExcess(
    const CAmount amount,
    const BlindingFactor& kernel_excess,
    const SecretKey& sender_key)
{
    const test::Tx output_template = test::TxBuilder()
        .AddOutput(amount, sender_key, StealthAddress::Random())
        .AddPeginKernel(amount)
        .Build();
    const test::TxOutput& output = output_template.GetOutputs().front();

    Kernel kernel = Kernel::Create(
        kernel_excess,
        std::nullopt,
        std::nullopt,
        amount,
        {},
        std::nullopt,
        {}
    );
    const Transaction::CPtr transaction = Transaction::Create(
        Blinds().Add(output.GetBlind()).Sub(kernel_excess).Total(),
        output_template.GetStealthOffset(),
        {},
        {output.GetOutput()},
        {std::move(kernel)}
    );
    BOOST_REQUIRE(!transaction->Validate());

    return test::Tx(transaction, {output});
}

Transaction::CPtr AddPlainKernel(
    const Transaction::CPtr& transaction,
    const Kernel& kernel,
    const BlindingFactor& kernel_excess)
{
    std::vector<Kernel> kernels = transaction->GetKernels();
    kernels.push_back(kernel);

    const Transaction::CPtr augmented = Transaction::Create(
        Blinds::From(transaction->GetKernelOffset()).Sub(kernel_excess).Total(),
        transaction->GetStealthOffset(),
        transaction->GetInputs(),
        transaction->GetOutputs(),
        std::move(kernels)
    );
    BOOST_REQUIRE(!augmented->Validate());
    return augmented;
}

void CheckBlock(
    const mw::BlockBuilder& builder,
    const std::vector<PegInCoin>& pegins)
{
    const Block::Ptr block = builder.BuildBlock();
    BOOST_REQUIRE(BlockValidator::ValidateBlock(block, pegins, {}));
    BOOST_REQUIRE(!KernelSumValidator::ValidateForBlock(
        block->GetTxBody(), block->GetKernelOffset(), BlindingFactor{}));
}

} // namespace

// Reject a shared kernel across valid transactions while keeping the first staged body valid.
BOOST_AUTO_TEST_CASE(RejectsDuplicateStagedKernels)
{
    auto db_view = CoinsViewDB::Open(m_path_root, nullptr, GetDB());
    auto cached_view = std::make_shared<CoinsViewCache>(db_view);
    mw::BlockBuilder builder(1, cached_view);

    const test::Tx first = test::Tx::CreatePegIn(1'000);
    const test::Tx second = test::Tx::CreatePegIn(2'000);
    const BlindingFactor shared_excess = BlindingFactor::Random();
    const Kernel shared_kernel = Kernel::Create(
        shared_excess,
        std::nullopt,
        CAmount{0},
        std::nullopt,
        {},
        std::nullopt,
        {}
    );
    const Transaction::CPtr first_with_shared = AddPlainKernel(
        first.GetTransaction(), shared_kernel, shared_excess
    );
    const Transaction::CPtr second_with_shared = AddPlainKernel(
        second.GetTransaction(), shared_kernel, shared_excess
    );

    BOOST_REQUIRE(builder.AddTransaction(first_with_shared, first.GetPegIns()));
    BOOST_CHECK(!builder.AddTransaction(second_with_shared, second.GetPegIns()));
    CheckBlock(builder, first.GetPegIns());
}

// Reject cancelling kernel excesses, then accept a compatible candidate without retaining failed state.
BOOST_AUTO_TEST_CASE(RejectsAggregateKernelIdentity)
{
    auto db_view = CoinsViewDB::Open(m_path_root, nullptr, GetDB());
    auto cached_view = std::make_shared<CoinsViewCache>(db_view);
    mw::BlockBuilder builder(1, cached_view);

    const BlindingFactor first_excess = BlindingFactor::Random();
    const BlindingFactor opposite_excess = Blinds().Sub(first_excess).Total();
    const test::Tx first = CreatePegInWithExcess(1'000, first_excess, SecretKey::Random());
    const test::Tx cancelling = CreatePegInWithExcess(2'000, opposite_excess, SecretKey::Random());
    const test::Tx compatible = test::Tx::CreatePegIn(3'000);

    BOOST_REQUIRE(builder.AddTransaction(first.GetTransaction(), first.GetPegIns()));
    BOOST_CHECK(!builder.AddTransaction(cancelling.GetTransaction(), cancelling.GetPegIns()));
    BOOST_REQUIRE(builder.AddTransaction(compatible.GetTransaction(), compatible.GetPegIns()));

    std::vector<PegInCoin> accepted_pegins = first.GetPegIns();
    const std::vector<PegInCoin> compatible_pegins = compatible.GetPegIns();
    accepted_pegins.insert(accepted_pegins.end(), compatible_pegins.begin(), compatible_pegins.end());
    CheckBlock(builder, accepted_pegins);
}

// Reject an aggregate commitment identity and allow a later compatible transaction.
BOOST_AUTO_TEST_CASE(RejectsAggregateCommitmentIdentity)
{
    auto db_view = CoinsViewDB::Open(m_path_root, nullptr, GetDB());
    auto cached_view = std::make_shared<CoinsViewCache>(db_view);
    mw::BlockBuilder builder(1, cached_view);

    const test::Tx first = test::Tx::CreatePegIn(1'000);
    const test::Tx cancelling = test::Tx::CreatePegOut(first.GetOutputs().front());
    const test::Tx compatible = test::Tx::CreatePegIn(2'000);

    BOOST_REQUIRE(builder.AddTransaction(first.GetTransaction(), first.GetPegIns()));
    BOOST_CHECK(!builder.AddTransaction(cancelling.GetTransaction(), {}));
    BOOST_REQUIRE(builder.AddTransaction(compatible.GetTransaction(), compatible.GetPegIns()));

    std::vector<PegInCoin> accepted_pegins = first.GetPegIns();
    const std::vector<PegInCoin> compatible_pegins = compatible.GetPegIns();
    accepted_pegins.insert(accepted_pegins.end(), compatible_pegins.begin(), compatible_pegins.end());
    CheckBlock(builder, accepted_pegins);
}

// Reject cancelling stealth keys without changing the accepted aggregate.
BOOST_AUTO_TEST_CASE(RejectsAggregateStealthIdentity)
{
    auto db_view = CoinsViewDB::Open(m_path_root, nullptr, GetDB());
    auto cached_view = std::make_shared<CoinsViewCache>(db_view);
    mw::BlockBuilder builder(1, cached_view);

    const SecretKey first_sender = SecretKey::Random();
    const BlindingFactor opposite_sender_blind = Blinds().Sub(first_sender).Total();
    const SecretKey opposite_sender(opposite_sender_blind.data());
    const test::Tx first = CreatePegInWithExcess(1'000, BlindingFactor::Random(), first_sender);
    const test::Tx cancelling = CreatePegInWithExcess(2'000, BlindingFactor::Random(), opposite_sender);

    BOOST_REQUIRE(builder.AddTransaction(first.GetTransaction(), first.GetPegIns()));
    BOOST_CHECK(!builder.AddTransaction(cancelling.GetTransaction(), cancelling.GetPegIns()));
    CheckBlock(builder, first.GetPegIns());
}

BOOST_AUTO_TEST_SUITE_END()
