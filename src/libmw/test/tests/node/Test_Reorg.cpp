// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/node/CoinsView.h>
#include <mw/node/BlockValidator.h>
#include <mw/crypto/SecretKeys.h>
#include <mw/crypto/Hasher.h>
#include <mw/crypto/KeyDerivation.h>

#include <test_framework/Miner.h>
#include <test_framework/TestMWEB.h>
#include <test_framework/TxBuilder.h>

BOOST_FIXTURE_TEST_SUITE(TestReorg, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(ReorgChain)
{
    auto pDatabase = GetDB();

    auto pDBView = mw::CoinsViewDB::Open(m_path_root, nullptr, pDatabase);
    BOOST_REQUIRE(pDBView != nullptr);

    auto pCachedView = std::make_shared<mw::CoinsViewCache>(pDBView);

    test::Miner miner(m_path_root);

    ///////////////////////
    // Mine Block 1
    ///////////////////////
    test::Tx block1_tx1 = test::Tx::CreatePegIn(1000);
    auto block1 = miner.MineBlock(160, { block1_tx1 });
    BOOST_REQUIRE(BlockValidator::ValidateBlock(block1.GetBlock(), { block1_tx1.GetPegInCoin() }, {}));
    pCachedView->ApplyBlock(block1.GetBlock());

    const auto& block1_tx1_output1 = block1_tx1.GetOutputs()[0];
    BOOST_CHECK(pDBView->GetCoin(block1_tx1_output1.GetOutputID()) == nullptr);
    BOOST_CHECK(pCachedView->GetCoin(block1_tx1_output1.GetOutputID()) != nullptr);

    ///////////////////////
    // Mine Block 2
    ///////////////////////
    SecretKey subaddr_scan_key = SecretKey::Random();
    SecretKey subaddr_spend_key = SecretKey::Random();
    StealthAddress receiver_addr(PublicKey::From(subaddr_scan_key), PublicKey::From(subaddr_spend_key));
    SecretKey sender_key = SecretKey::Random();

    test::Tx block2_tx1 = test::TxBuilder()
        .AddPeginKernel(500)
        .AddOutput(500, sender_key, receiver_addr)
        .Build();
    const auto& block2_tx1_output1 = block2_tx1.GetOutputs()[0];

    SecretKey shared_secret = mw::DeriveSharedSecret(sender_key, receiver_addr, block2_tx1_output1.GetAmount());
    SecretKey output_spend_key = mw::DeriveOutputSpendKey(subaddr_spend_key, shared_secret);

    test::Tx block2_tx2 = test::TxBuilder()
        .AddInput(
            block2_tx1_output1.GetAmount(),
            output_spend_key,
            block2_tx1_output1.GetBlind(),
            block2_tx1_output1.GetOutputID()
        )
        .AddOutput(block2_tx1_output1.GetAmount(), SecretKey::Random(), StealthAddress::Random())
        .AddPlainKernel(0)
        .Build();
    auto block2 = miner.MineBlock(161, { block2_tx1, block2_tx2 });
    BOOST_REQUIRE(BlockValidator::ValidateBlock(block2.GetBlock(), { block2_tx1.GetPegInCoin() }, {}));
    mw::BlockUndo::CPtr undoBlock2 = pCachedView->ApplyBlock(block2.GetBlock());

    const auto& block2_tx2_output1 = block2_tx2.GetOutputs()[0];
    BOOST_CHECK(pDBView->GetCoin(block2_tx1_output1.GetOutputID()) == nullptr);
    BOOST_CHECK(pDBView->GetCoin(block2_tx2_output1.GetOutputID()) == nullptr);
    BOOST_CHECK(pCachedView->GetCoin(block2_tx1_output1.GetOutputID()) == nullptr);
    BOOST_CHECK(pCachedView->GetCoin(block2_tx2_output1.GetOutputID()) != nullptr);

    ///////////////////////
    // Disconnect Block 2
    ///////////////////////
    pCachedView->UndoBlock(undoBlock2);
    BOOST_CHECK(pCachedView->GetCoin(block1_tx1_output1.GetOutputID()) != nullptr);
    BOOST_CHECK(pCachedView->GetCoin(block2_tx1_output1.GetOutputID()) == nullptr);
    BOOST_CHECK(pCachedView->GetCoin(block2_tx2_output1.GetOutputID()) == nullptr);
    miner.Rewind(1);

    ///////////////////////
    // Mine Block 3
    ///////////////////////
    test::Tx block3_tx1 = test::Tx::CreatePegIn(1500);
    auto block3 = miner.MineBlock(161, { block3_tx1 });
    BOOST_REQUIRE(BlockValidator::ValidateBlock(block3.GetBlock(), {block3_tx1.GetPegInCoin()}, {}));
    pCachedView->ApplyBlock(block3.GetBlock());

    const auto& block3_tx1_output1 = block3_tx1.GetOutputs()[0];
    BOOST_CHECK(pDBView->GetCoin(block3_tx1_output1.GetOutputID()) == nullptr);
    BOOST_CHECK(pCachedView->GetCoin(block3_tx1_output1.GetOutputID()) != nullptr);

    ///////////////////////
    // Flush View
    ///////////////////////
    CDBBatch batch(*pDatabase);
    pCachedView->Flush(&batch);
    pDatabase->WriteBatch(batch);

    BOOST_CHECK(pDBView->GetCoin(block1_tx1_output1.GetOutputID()) != nullptr);
    BOOST_CHECK(pCachedView->GetCoin(block1_tx1_output1.GetOutputID()) != nullptr);
    BOOST_CHECK(pDBView->GetCoin(block2_tx1_output1.GetOutputID()) == nullptr);
    BOOST_CHECK(pCachedView->GetCoin(block2_tx1_output1.GetOutputID()) == nullptr);
    BOOST_CHECK(pDBView->GetCoin(block3_tx1_output1.GetOutputID()) != nullptr);
    BOOST_CHECK(pCachedView->GetCoin(block3_tx1_output1.GetOutputID()) != nullptr);
}

BOOST_AUTO_TEST_SUITE_END()
