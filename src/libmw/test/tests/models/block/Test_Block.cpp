// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/models/block/Block.h>
#include <mw/consensus/Aggregation.h>
#include <mw/consensus/Params.h>
#include <mw/exceptions/ValidationException.h>
#include <mw/mmr/MMR.h>
#include <test_framework/models/Tx.h>

#include <test_framework/TestMWEB.h>

namespace {
mw::Block BuildBlock(const int32_t height, const mw::Transaction::CPtr& pTransaction)
{
    MemMMR kernel_mmr;
    for (const mw::Kernel& kernel : pTransaction->GetKernels()) {
        kernel_mmr.Add(kernel);
    }

    mw::Header::CPtr pHeader = std::make_shared<mw::Header>(
        height,
        mw::Hash::FromHex("000102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F20"),
        kernel_mmr.Root(),
        mw::Hash::FromHex("002102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F20"),
        pTransaction->GetKernelOffset(),
        pTransaction->GetStealthOffset(),
        pTransaction->GetOutputs().size(),
        pTransaction->GetKernels().size()
    );

    return mw::Block(pHeader, pTransaction->GetBody());
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(TestBlock, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(Block)
{
    test::Tx tx1 = test::Tx::CreatePegIn(10);
    test::Tx tx2 = test::Tx::CreatePegIn(20);
    mw::Transaction::CPtr pTransaction = Aggregation::Aggregate({
        tx1.GetTransaction(),
        tx2.GetTransaction()
    });

    MemMMR kernel_mmr;
    for (const mw::Kernel& kernel : pTransaction->GetKernels()) {
        kernel_mmr.Add(kernel);
    }

    mw::Header::CPtr pHeader = std::make_shared<mw::Header>(
        100,
        mw::Hash::FromHex("000102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F20"),
        kernel_mmr.Root(),
        mw::Hash::FromHex("002102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F20"),
        pTransaction->GetKernelOffset(),
        pTransaction->GetStealthOffset(),
        pTransaction->GetOutputs().size(),
        pTransaction->GetKernels().size()
    );

    mw::Block block(pHeader, pTransaction->GetBody());

    BOOST_REQUIRE(*block.GetHeader() == *pHeader);
    BOOST_REQUIRE(block.GetInputs() == pTransaction->GetInputs());
    BOOST_REQUIRE(block.GetOutputs() == pTransaction->GetOutputs());
    BOOST_REQUIRE(block.GetKernels() == pTransaction->GetKernels());
    BOOST_REQUIRE(block.GetHeight() == pHeader->GetHeight());
    BOOST_REQUIRE(block.GetKernelOffset() == pHeader->GetKernelOffset());
    BOOST_REQUIRE(block.GetStealthOffset() == pHeader->GetStealthOffset());

    BOOST_REQUIRE(block.GetPegIns() == pTransaction->GetPegIns());
    const auto pegin_amount = block.GetPegInAmount();
    BOOST_REQUIRE(pegin_amount.has_value());
    BOOST_REQUIRE(*pegin_amount == 30);
    BOOST_REQUIRE(block.GetPegOuts().empty());

    std::vector<uint8_t> block_serialized = block.Serialized();
    mw::Block block2;
    CDataStream(block_serialized, SER_DISK, 0) >> block2;
    BOOST_REQUIRE(*block.GetHeader() == *block2.GetHeader());
    BOOST_REQUIRE(block.GetTxBody() == block2.GetTxBody());

    BOOST_REQUIRE(!block.Validate());
}

BOOST_AUTO_TEST_CASE(Block_KernelLockHeight)
{
    const int32_t lock_height = mw::KERNEL_LOCK_HEIGHT_GRANDFATHER_HEIGHT + 2;
    mw::Kernel kernel = mw::Kernel::Create(
        BlindingFactor::Random(),
        std::nullopt,
        CAmount(0),
        std::nullopt,
        std::vector<PegOutCoin>{},
        lock_height,
        std::vector<uint8_t>{}
    );
    mw::Transaction::CPtr pTransaction = mw::Transaction::Create(
        BlindingFactor(),
        BlindingFactor(),
        {},
        {},
        {kernel}
    );

    mw::Block grandfathered_block = BuildBlock(mw::KERNEL_LOCK_HEIGHT_GRANDFATHER_HEIGHT, pTransaction);
    BOOST_REQUIRE(!grandfathered_block.Validate());

    mw::Block valid_block = BuildBlock(lock_height, pTransaction);
    BOOST_REQUIRE(!valid_block.Validate());

    mw::Block invalid_block = BuildBlock(lock_height - 1, pTransaction);
    BOOST_REQUIRE(invalid_block.Validate() == EConsensusError::LOCK_HEIGHT);
}

BOOST_AUTO_TEST_SUITE_END()
