#include <mw/crypto/SecretKeys.h>
#include <mw/node/BlockValidator.h>
#include <mw/node/CoinsView.h>

#include <test_framework/Miner.h>
#include <test_framework/TestMWEB.h>
#include <test_framework/models/Tx.h>

BOOST_FIXTURE_TEST_SUITE(TestCoinsView, MWEBTestingSetup)

static CAmount SumPegOuts(const std::vector<PegOutCoin>& pegouts)
{
    CAmount total = 0;
    for (const PegOutCoin& pegout : pegouts) {
        total += pegout.GetAmount();
    }

    return total;
}

static void CheckAmountAccounting(const mw::Block::CPtr& pBlock)
{
    const auto pegin_amount = pBlock->GetPegInAmount();
    const auto fee_amount = pBlock->GetTotalFee();
    const auto supply_change = pBlock->GetSupplyChange();

    BOOST_REQUIRE(pegin_amount);
    BOOST_REQUIRE(fee_amount);
    BOOST_REQUIRE(supply_change);
    BOOST_CHECK_EQUAL(*supply_change, *pegin_amount - SumPegOuts(pBlock->GetPegOuts()) - *fee_amount);
}

static void CheckMMRRoots(const mw::CoinsViewCache& view)
{
    BOOST_REQUIRE(view.GetBestHeader() != nullptr);
    BOOST_CHECK(view.GetBestHeader()->GetOutputRoot() == view.GetOutputPMMR()->Root());
    BOOST_CHECK_EQUAL(view.GetBestHeader()->GetNumTXOs(), view.GetOutputPMMR()->GetNumLeaves());
    BOOST_CHECK(view.GetBestHeader()->GetLeafsetRoot() == view.GetLeafSet()->Root());
}

BOOST_AUTO_TEST_CASE(ApplyBlock_AmountAccountingAndMMRRoots)
{
    auto pDBView = mw::CoinsViewDB::Open(GetDataDir(), nullptr, GetDB());
    auto pCachedView = std::make_shared<mw::CoinsViewCache>(pDBView);
    test::Miner miner(GetDataDir());

    CAmount expected_mweb_amount = 0;

    test::Tx pegin_tx = test::Tx::CreatePegIn(5'000'000);
    mw::Block::CPtr pBlock1 = miner.MineBlock(1, {pegin_tx}).GetBlock();
    BOOST_REQUIRE(BlockValidator::ValidateBlock(pBlock1, pegin_tx.GetPegIns(), pegin_tx.GetPegOuts()));
    CheckAmountAccounting(pBlock1);
    expected_mweb_amount += *pBlock1->GetSupplyChange();
    BOOST_CHECK_EQUAL(expected_mweb_amount, 5'000'000);
    pCachedView->ApplyBlock(pBlock1, false);
    CheckMMRRoots(*pCachedView);

    test::Tx pegout_tx = test::Tx::CreatePegOut(pegin_tx.GetOutputs().front(), 1'000);
    mw::Block::CPtr pBlock2 = miner.MineBlock(2, {pegout_tx}).GetBlock();
    BOOST_REQUIRE(BlockValidator::ValidateBlock(pBlock2, pegout_tx.GetPegIns(), pegout_tx.GetPegOuts()));
    CheckAmountAccounting(pBlock2);
    expected_mweb_amount += *pBlock2->GetSupplyChange();
    BOOST_CHECK_EQUAL(expected_mweb_amount, 0);
    pCachedView->ApplyBlock(pBlock2, false);
    CheckMMRRoots(*pCachedView);
}

BOOST_AUTO_TEST_CASE(ApplyBlock_RejectedBlockDoesNotMutateCache)
{
    auto pDBView = mw::CoinsViewDB::Open(GetDataDir(), nullptr, GetDB());
    auto pCachedView = std::make_shared<mw::CoinsViewCache>(pDBView);
    test::Miner miner(GetDataDir());

    test::Tx pegin_tx = test::Tx::CreatePegIn(5'000'000);
    mw::Block::CPtr pBlock1 = miner.MineBlock(1, {pegin_tx}).GetBlock();
    BOOST_REQUIRE(BlockValidator::ValidateBlock(pBlock1, pegin_tx.GetPegIns(), pegin_tx.GetPegOuts()));
    pCachedView->ApplyBlock(pBlock1, false);

    const mw::Header::CPtr best_header_before = pCachedView->GetBestHeader();
    const mw::Hash output_root_before = pCachedView->GetOutputPMMR()->Root();
    const uint64_t num_txos_before = pCachedView->GetOutputPMMR()->GetNumLeaves();
    const mw::Hash leafset_root_before = pCachedView->GetLeafSet()->Root();

    test::Tx next_pegin_tx = test::Tx::CreatePegIn(2'000'000);
    mw::Block::CPtr pBlock2 = miner.MineBlock(2, {next_pegin_tx}).GetBlock();
    BOOST_REQUIRE(BlockValidator::ValidateBlock(pBlock2, next_pegin_tx.GetPegIns(), next_pegin_tx.GetPegOuts()));

    mw::Block::CPtr pBadBlock = std::make_shared<mw::Block>(
        mw::MutHeader(pBlock2->GetHeader())
            .SetOutputRoot(SecretKey::Random().GetBigInt())
            .Build(),
        pBlock2->GetTxBody()
    );

    BOOST_CHECK_THROW(pCachedView->ApplyBlock(pBadBlock, false), std::exception);
    BOOST_REQUIRE(pCachedView->GetBestHeader() != nullptr);
    BOOST_CHECK(pCachedView->GetBestHeader()->GetHash() == best_header_before->GetHash());
    BOOST_CHECK(pCachedView->GetOutputPMMR()->Root() == output_root_before);
    BOOST_CHECK_EQUAL(pCachedView->GetOutputPMMR()->GetNumLeaves(), num_txos_before);
    BOOST_CHECK(pCachedView->GetLeafSet()->Root() == leafset_root_before);
    BOOST_CHECK(pCachedView->GetUTXO(pegin_tx.GetOutputs().front().GetOutputID()) != nullptr);
    BOOST_CHECK(pCachedView->GetUTXO(next_pegin_tx.GetOutputs().front().GetOutputID()) == nullptr);
}

BOOST_AUTO_TEST_SUITE_END()