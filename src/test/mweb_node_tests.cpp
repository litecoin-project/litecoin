// Copyright (c) 2025 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <consensus/validation.h>
#include <dbwrapper.h>
#include <mweb/mweb_node.h>
#include <mw/crypto/KeyDerivation.h>
#include <mw/crypto/PublicKeys.h>
#include <mw/crypto/SecretKeys.h>
#include <mw/models/block/Block.h>
#include <mw/models/block/Header.h>
#include <mw/models/tx/MutableTx.h>
#include <mw/models/wallet/StealthAddress.h>
#include <mw/node/CoinsView.h>
#include <primitives/block.h>
#include <script/standard.h>
#include <test/util/setup_common.h>
#include <undo.h>
#include <validation.h>

#include <test_framework/Miner.h>
#include <test_framework/TxBuilder.h>

#include <boost/test/unit_test.hpp>

#include <cassert>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace {

static constexpr CAmount PREVIOUS_MWEB_AMOUNT{10'000'000};
static constexpr CAmount PEGIN_AMOUNT{10'000'000};
static constexpr CAmount PEGOUT_AMOUNT{4'000'000};
static constexpr CAmount MWEB_FEE{1'000'000};
static constexpr CAmount MWEB_OUTPUT_AMOUNT{5'000'000};

CTransactionRef MakeCoinbase()
{
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vout.emplace_back(50 * COIN, CScript() << OP_TRUE);
    return MakeTransactionRef(std::move(coinbase));
}

void ReplaceTransaction(CBlock& block, const size_t index, CMutableTransaction transaction)
{
    block.vtx[index] = MakeTransactionRef(std::move(transaction));
}

CBlock BuildCanonicalBlock(
    const test::MinedBlock& mined_block,
    const std::optional<COutPoint>& previous_hogaddr,
    const CAmount previous_mweb_amount)
{
    CBlock block;
    block.vtx.push_back(MakeCoinbase());
    block.mweb_block = MWEB::Block{mined_block.GetBlock()};

    const std::vector<PegInCoin> pegins = mined_block.GetBlock()->GetPegIns();
    if (!pegins.empty()) {
        CMutableTransaction pegin_transaction;
        for (const PegInCoin& pegin : pegins) {
            pegin_transaction.vout.emplace_back(
                pegin.GetAmount(),
                GetScriptForPegin(pegin.GetKernelID()));
        }
        block.vtx.push_back(MakeTransactionRef(std::move(pegin_transaction)));
    }

    CMutableTransaction hogex;
    hogex.m_hogEx = true;
    if (previous_hogaddr.has_value()) {
        hogex.vin.emplace_back(*previous_hogaddr);
    }

    if (!pegins.empty()) {
        const CTransactionRef& pegin_transaction = block.vtx.back();
        for (size_t i = 0; i < pegins.size(); ++i) {
            hogex.vin.emplace_back(pegin_transaction->GetHash(), i);
        }
    }

    const std::optional<CAmount> supply_change = mined_block.GetBlock()->GetSupplyChange();
    assert(supply_change.has_value());
    hogex.vout.emplace_back(
        previous_mweb_amount + *supply_change,
        CScript() << OP_8 << mined_block.GetHash().vec());

    for (const PegOutCoin& pegout : mined_block.GetBlock()->GetPegOuts()) {
        hogex.vout.emplace_back(pegout.GetAmount(), pegout.GetScriptPubKey());
    }

    block.vtx.push_back(MakeTransactionRef(std::move(hogex)));
    return block;
}

/**
 * A small fixture for rules that apply before MWEB activation. The regtest
 * genesis block predates the default MWEB deployment start time.
 */
struct InactiveMWEBNodeTestingSetup : public TestingSetup
{
    InactiveMWEBNodeTestingSetup()
        : TestingSetup{CBaseChainParams::REGTEST},
          m_miner{m_path_root / "inactive_mweb_miner"}
    {
    }

    const CBlockIndex* PreviousBlock() const
    {
        return Assert(m_node.chainman)->ActiveChain().Tip();
    }

    test::Miner m_miner;
};

/**
 * Builds canonical blocks around valid libmw blocks. MWEB is always active in
 * this fixture, and the synthetic previous block represents an already-active
 * chain. Tests can therefore describe only the rule they intend to exercise.
 */
class MWEBNodeTestingSetup : public TestingSetup
{
public:
    explicit MWEBNodeTestingSetup(const bool fund_previous_block = false)
        : TestingSetup{
              CBaseChainParams::REGTEST,
              {"-vbparams=mweb:-1:9223372036854775807"}},
          m_db{std::make_unique<CDBWrapper>(m_path_root / "mweb_node_db", 1 << 15)},
          m_miner{m_path_root / "mweb_node_miner"}
    {
        std::vector<test::Tx> previous_transactions;
        if (fund_previous_block) {
            const SecretKey scan_key = SecretKey::Random();
            const SecretKey spend_key = SecretKey::Random();
            const StealthAddress address{
                PublicKey::From(scan_key),
                PublicKey::From(spend_key)};
            const SecretKey sender_key = SecretKey::Random();

            m_funding_tx = test::TxBuilder()
                .AddPeginKernel(PREVIOUS_MWEB_AMOUNT)
                .AddOutput(PREVIOUS_MWEB_AMOUNT, sender_key, address)
                .Build();
            const SecretKey shared_secret = mw::DeriveSharedSecret(
                sender_key,
                address,
                PREVIOUS_MWEB_AMOUNT);
            m_funding_output_spend_key = mw::DeriveOutputSpendKey(spend_key, shared_secret);
            previous_transactions.push_back(*m_funding_tx);
        }

        const test::MinedBlock previous_mweb_block = m_miner.MineBlock(1, previous_transactions);
        m_base_view = mw::CoinsViewDB::Open(
            m_path_root / "mweb_node_view",
            nullptr,
            m_db.get());
        m_view = std::make_shared<mw::CoinsViewCache>(m_base_view);
        m_view->ApplyBlock(previous_mweb_block.GetBlock());

        m_previous.nHeight = 1;
        m_previous.mweb_header = previous_mweb_block.GetHeader();
        m_previous.hogex_hash = uint256::ONE;
        m_previous.mweb_amount = fund_previous_block ? PREVIOUS_MWEB_AMOUNT : 0;
    }

    const Consensus::Params& ConsensusParams() const
    {
        return Assert(m_node.chainman)->GetConsensus();
    }

    CBlock BuildBlock(const std::vector<test::Tx>& mweb_transactions = {})
    {
        const test::MinedBlock mined_block = m_miner.MineBlock(
            m_previous.nHeight + 1,
            mweb_transactions);
        return BuildCanonicalBlock(
            mined_block,
            COutPoint{m_previous.hogex_hash, 0},
            m_previous.mweb_amount);
    }

    test::Tx BuildPeginAndPegout() const
    {
        return test::TxBuilder()
            .AddPeginKernel(PEGIN_AMOUNT)
            .AddOutput(MWEB_OUTPUT_AMOUNT)
            .AddPegoutKernel(PEGOUT_AMOUNT, MWEB_FEE)
            .Build();
    }

    test::Tx BuildPeginWithFee() const
    {
        return test::TxBuilder()
            .AddPeginKernel(PEGIN_AMOUNT)
            .AddOutput(PEGIN_AMOUNT - MWEB_FEE)
            .AddPlainKernel(MWEB_FEE)
            .Build();
    }

    test::Tx BuildSpendOfPreviousOutput() const
    {
        assert(m_funding_tx.has_value());
        assert(m_funding_output_spend_key.has_value());
        const test::TxOutput& funding_output = m_funding_tx->GetOutputs().front();
        return test::TxBuilder()
            .AddInput(
                funding_output.GetAmount(),
                *m_funding_output_spend_key,
                funding_output.GetBlind(),
                funding_output.GetOutputID())
            .AddOutput(PREVIOUS_MWEB_AMOUNT - MWEB_FEE)
            .AddPlainKernel(MWEB_FEE)
            .Build();
    }

    void ExpectContextualBlock(const CBlock& block)
    {
        BlockValidationState state;
        BOOST_CHECK_MESSAGE(
            MWEB::Node::ContextualCheckBlock(
                block,
                ConsensusParams(),
                *Assert(m_node.chainman),
                &m_previous,
                state),
            state.ToString());
        BOOST_CHECK(state.IsValid());
    }

    void ExpectContextualReject(
        const CBlock& block,
        const BlockValidationResult result,
        const std::string& reason)
    {
        BlockValidationState state;
        BOOST_CHECK(!MWEB::Node::ContextualCheckBlock(
            block,
            ConsensusParams(),
            *Assert(m_node.chainman),
            &m_previous,
            state));
        BOOST_CHECK_EQUAL(state.GetResult(), result);
        BOOST_CHECK_EQUAL(state.GetRejectReason(), reason);
    }

    void ExpectConnectReject(
        const CBlock& block,
        const BlockValidationResult result,
        const std::string& reason,
        const Consensus::Params* params = nullptr)
    {
        CBlockUndo block_undo;
        BlockValidationState state;
        BOOST_CHECK(!MWEB::Node::ConnectBlock(
            block,
            params == nullptr ? ConsensusParams() : *params,
            *Assert(m_node.chainman),
            &m_previous,
            block_undo,
            *m_view,
            state));
        BOOST_CHECK_EQUAL(state.GetResult(), result);
        BOOST_CHECK_EQUAL(state.GetRejectReason(), reason);
    }

    CBlockIndex m_previous;
    std::unique_ptr<CDBWrapper> m_db;
    mw::CoinsViewDB::Ptr m_base_view;
    mw::CoinsViewCache::Ptr m_view;
    test::Miner m_miner;
    std::optional<test::Tx> m_funding_tx;
    std::optional<SecretKey> m_funding_output_spend_key;
};

struct FundedMWEBNodeTestingSetup : public MWEBNodeTestingSetup
{
    FundedMWEBNodeTestingSetup()
        : MWEBNodeTestingSetup{/*fund_previous_block=*/true}
    {
    }
};

/** A short in-memory BIP8 chain whose next block is the first active block. */
class MWEBActivationBoundaryTestingSetup : public TestingSetup
{
public:
    MWEBActivationBoundaryTestingSetup()
        : TestingSetup{
              CBaseChainParams::REGTEST,
              {"-vbparams=mweb:0:0:0:144"}},
          m_db{std::make_unique<CDBWrapper>(m_path_root / "mweb_activation_db", 1 << 15)},
          m_miner{m_path_root / "mweb_activation_miner"}
    {
        m_chain.reserve(432);
        for (int height = 0; height < 432; ++height) {
            auto index = std::make_unique<CBlockIndex>();
            index->nHeight = height;
            index->pprev = m_chain.empty() ? nullptr : m_chain.back().get();
            m_chain.push_back(std::move(index));
        }

        m_base_view = mw::CoinsViewDB::Open(
            m_path_root / "mweb_activation_view",
            nullptr,
            m_db.get());
        m_view = std::make_shared<mw::CoinsViewCache>(m_base_view);
    }

    const CBlockIndex* PreviousBlock() const
    {
        return m_chain.back().get();
    }

    CBlock BuildFirstMWEBBlock(const std::vector<test::Tx>& transactions = {})
    {
        return BuildCanonicalBlock(
            m_miner.MineBlock(432, transactions),
            std::nullopt,
            /*previous_mweb_amount=*/0);
    }

    std::vector<std::unique_ptr<CBlockIndex>> m_chain;
    std::unique_ptr<CDBWrapper> m_db;
    mw::CoinsViewDB::Ptr m_base_view;
    mw::CoinsViewCache::Ptr m_view;
    test::Miner m_miner;
};

CMutableTransaction HybridPeginTransaction(
    const test::Tx& mweb_transaction,
    const CAmount canonical_amount,
    const mw::Hash& canonical_kernel_id)
{
    CMutableTransaction transaction;
    transaction.vout.emplace_back(
        canonical_amount,
        GetScriptForPegin(canonical_kernel_id));
    transaction.mweb_tx = mw::MutableTx::From(*mweb_transaction.GetTransaction());
    return transaction;
}

mw::Kernel AddEmptyFeature(const mw::Kernel& kernel, const mw::Kernel::FeatureBit feature)
{
    mw::MutableKernel mutable_kernel;
    mutable_kernel.Update(kernel);
    assert(mutable_kernel.excess.has_value());
    assert(mutable_kernel.signature.has_value());

    return mw::Kernel{
        static_cast<uint8_t>(kernel.GetFeatures() | feature),
        mutable_kernel.fee,
        mutable_kernel.pegin,
        mutable_kernel.GetPegOuts(),
        mutable_kernel.lock_height,
        mutable_kernel.stealth_excess,
        mutable_kernel.extradata,
        *mutable_kernel.excess,
        *mutable_kernel.signature};
}

BOOST_FIXTURE_TEST_SUITE(mweb_node_contextual_tests, MWEBNodeTestingSetup)

// A block containing both a pegin and a pegout passes when its canonical and MWEB data agree.
BOOST_AUTO_TEST_CASE(ValidBlockWithPeginAndPegoutPasses)
{
    const test::Tx transaction = BuildPeginAndPegout();
    ExpectContextualBlock(BuildBlock({transaction}));
}

// Removing the required extension block after activation produces a mutated-block rejection.
BOOST_AUTO_TEST_CASE(MissingExtensionBlockIsMutated)
{
    CBlock block = BuildBlock();
    block.mweb_block.SetNull();

    ExpectContextualReject(block, BlockValidationResult::BLOCK_MUTATED, "mweb-missing");
}

// Leaving MWEB transaction data attached to a canonical pegin transaction is rejected as mutated data.
BOOST_AUTO_TEST_CASE(AttachedMWEBTransactionIsMutated)
{
    const test::Tx transaction = test::Tx::CreatePegIn(PEGIN_AMOUNT);
    CBlock block = BuildBlock({transaction});
    CMutableTransaction pegin_transaction{*block.vtx[1]};
    pegin_transaction.mweb_tx = mw::MutableTx::From(*transaction.GetTransaction());
    ReplaceTransaction(block, 1, std::move(pegin_transaction));

    ExpectContextualReject(block, BlockValidationResult::BLOCK_MUTATED, "unexpected-mweb-data");
}

// Clearing the final transaction's HogEx marker is rejected as mutated data.
BOOST_AUTO_TEST_CASE(MissingHogExMarkerIsMutated)
{
    CBlock block = BuildBlock();
    CMutableTransaction hogex{*block.vtx.back()};
    hogex.m_hogEx = false;
    ReplaceTransaction(block, block.vtx.size() - 1, std::move(hogex));

    ExpectContextualReject(block, BlockValidationResult::BLOCK_MUTATED, "hogex-missing");
}

// Marking the coinbase as another HogEx is rejected even when the final HogEx is present.
BOOST_AUTO_TEST_CASE(HogExBeforeFinalTransactionIsMutated)
{
    CBlock block = BuildBlock();
    CMutableTransaction coinbase{*block.vtx.front()};
    coinbase.m_hogEx = true;
    ReplaceTransaction(block, 0, std::move(coinbase));

    ExpectContextualReject(block, BlockValidationResult::BLOCK_MUTATED, "bad-hogex-position");
}

// Adding a pegin output to the coinbase violates the block's consensus rules.
BOOST_AUTO_TEST_CASE(PeginInCoinbaseIsConsensusInvalid)
{
    CBlock block = BuildBlock();
    CMutableTransaction coinbase{*block.vtx.front()};
    coinbase.vout.emplace_back(PEGIN_AMOUNT, GetScriptForPegin(mw::Hash::ValueOf(1)));
    ReplaceTransaction(block, 0, std::move(coinbase));

    ExpectContextualReject(block, BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-unexpected-pegin");
}

// Adding a pegin output to the HogEx violates the block's consensus rules.
BOOST_AUTO_TEST_CASE(PeginInHogExIsConsensusInvalid)
{
    CBlock block = BuildBlock();
    CMutableTransaction hogex{*block.vtx.back()};
    hogex.vout.emplace_back(PEGIN_AMOUNT, GetScriptForPegin(mw::Hash::ValueOf(1)));
    ReplaceTransaction(block, block.vtx.size() - 1, std::move(hogex));

    ExpectContextualReject(block, BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-unexpected-pegin");
}

// Replacing the first HogEx output's HogAddr script with OP_TRUE causes a consensus rejection.
BOOST_AUTO_TEST_CASE(InvalidHogAddrIsConsensusInvalid)
{
    CBlock block = BuildBlock();
    CMutableTransaction hogex{*block.vtx.back()};
    hogex.vout.front().scriptPubKey = CScript() << OP_TRUE;
    ReplaceTransaction(block, block.vtx.size() - 1, std::move(hogex));

    ExpectContextualReject(block, BlockValidationResult::BLOCK_CONSENSUS, "bad-hogex");
}

// A valid HogAddr script committing to the wrong MWEB header hash is rejected as mutated data.
BOOST_AUTO_TEST_CASE(HogAddrWithWrongHeaderHashIsMutated)
{
    CBlock block = BuildBlock();
    CMutableTransaction hogex{*block.vtx.back()};
    hogex.vout.front().scriptPubKey = CScript() << OP_8 << mw::Hash::ValueOf(1).vec();
    ReplaceTransaction(block, block.vtx.size() - 1, std::move(hogex));

    ExpectContextualReject(block, BlockValidationResult::BLOCK_MUTATED, "mweb-hash-mismatch");
}

// An MWEB header with the wrong height is rejected even when the HogAddr commits to that header.
BOOST_AUTO_TEST_CASE(WrongExtensionBlockHeightIsConsensusInvalid)
{
    CBlock block = BuildBlock();
    const mw::Block::CPtr wrong_height_block = std::make_shared<mw::Block>(
        mw::MutHeader{block.mweb_block.GetMWEBHeader()}
            .SetHeight(block.mweb_block.GetHeight() + 1)
            .Build(),
        block.mweb_block.m_block->GetTxBody());
    block.mweb_block = MWEB::Block{wrong_height_block};

    CMutableTransaction hogex{*block.vtx.back()};
    hogex.vout.front().scriptPubKey = CScript() << OP_8 << wrong_height_block->GetHash().vec();
    ReplaceTransaction(block, block.vtx.size() - 1, std::move(hogex));

    ExpectContextualReject(block, BlockValidationResult::BLOCK_CONSENSUS, "mweb-height-mismatch");
}

// With the pegout feature rule active, signaling pegouts without supplying any causes a consensus rejection.
BOOST_AUTO_TEST_CASE(EmptyPegoutFeatureIsConsensusInvalid)
{
    const test::Tx transaction = test::Tx::CreatePegIn(PEGIN_AMOUNT);
    CBlock block = BuildBlock({transaction});
    const mw::Kernel kernel = AddEmptyFeature(
        block.mweb_block.m_block->GetKernels().front(),
        mw::Kernel::PEGOUT_FEATURE_BIT);
    block.mweb_block = MWEB::Block{
        mw::MutBlock{block.mweb_block.m_block}.SetKernels({kernel}).Build()};

    ExpectContextualReject(block, BlockValidationResult::BLOCK_CONSENSUS, "bad-mweb-empty-pegout");
}

// With the extra data feature rule active, signaling extra data with an empty payload causes a consensus rejection.
BOOST_AUTO_TEST_CASE(EmptyExtraDataFeatureIsConsensusInvalid)
{
    const test::Tx transaction = test::Tx::CreatePegIn(PEGIN_AMOUNT);
    CBlock block = BuildBlock({transaction});
    const mw::Kernel kernel = AddEmptyFeature(
        block.mweb_block.m_block->GetKernels().front(),
        mw::Kernel::EXTRA_DATA_FEATURE_BIT);
    block.mweb_block = MWEB::Block{
        mw::MutBlock{block.mweb_block.m_block}.SetKernels({kernel}).Build()};

    ExpectContextualReject(block, BlockValidationResult::BLOCK_CONSENSUS, "bad-mweb-empty-extradata");
}

// Removing the HogEx input that spends a canonical pegin output causes a consensus rejection.
BOOST_AUTO_TEST_CASE(MissingPeginFromHogExIsConsensusInvalid)
{
    const test::Tx transaction = test::Tx::CreatePegIn(PEGIN_AMOUNT);
    CBlock block = BuildBlock({transaction});
    CMutableTransaction hogex{*block.vtx.back()};
    hogex.vin.pop_back();
    ReplaceTransaction(block, block.vtx.size() - 1, std::move(hogex));

    ExpectContextualReject(block, BlockValidationResult::BLOCK_CONSENSUS, "pegins-missing");
}

// Redirecting a HogEx pegin input to the wrong transaction causes a consensus rejection.
BOOST_AUTO_TEST_CASE(MismatchedPeginInHogExIsConsensusInvalid)
{
    const test::Tx transaction = test::Tx::CreatePegIn(PEGIN_AMOUNT);
    CBlock block = BuildBlock({transaction});
    CMutableTransaction hogex{*block.vtx.back()};
    hogex.vin.back().prevout.hash = uint256::ONE;
    ReplaceTransaction(block, block.vtx.size() - 1, std::move(hogex));

    ExpectContextualReject(block, BlockValidationResult::BLOCK_CONSENSUS, "pegin-mismatch");
}

// An empty extension block permits only the previous HogAddr input; an additional HogEx input is rejected.
BOOST_AUTO_TEST_CASE(ExtraHogExInputIsConsensusInvalid)
{
    CBlock block = BuildBlock();
    CMutableTransaction hogex{*block.vtx.back()};
    hogex.vin.emplace_back(uint256::ONE, 1);
    ReplaceTransaction(block, block.vtx.size() - 1, std::move(hogex));

    ExpectContextualReject(block, BlockValidationResult::BLOCK_CONSENSUS, "extra-hogex-input");
}

// Increase the canonical pegin amount and update its HogEx reference; the mismatch with the MWEB kernel is rejected.
BOOST_AUTO_TEST_CASE(CanonicalPeginAmountMustMatchExtensionBlock)
{
    const test::Tx transaction = test::Tx::CreatePegIn(PEGIN_AMOUNT);
    CBlock block = BuildBlock({transaction});
    CMutableTransaction pegin_transaction{*block.vtx[1]};
    pegin_transaction.vout.front().nValue += 1;
    ReplaceTransaction(block, 1, std::move(pegin_transaction));

    // Keep the HogEx input pointing to the newly-hashed canonical transaction.
    CMutableTransaction hogex{*block.vtx.back()};
    hogex.vin.back().prevout.hash = block.vtx[1]->GetHash();
    ReplaceTransaction(block, block.vtx.size() - 1, std::move(hogex));

    ExpectContextualReject(block, BlockValidationResult::BLOCK_MUTATED, "bad-blk-mweb");
}

// Increasing a HogEx pegout amount without changing its MWEB kernel is rejected as mutated data.
BOOST_AUTO_TEST_CASE(HogExPegoutMustMatchExtensionBlock)
{
    const test::Tx transaction = BuildPeginAndPegout();
    CBlock block = BuildBlock({transaction});
    CMutableTransaction hogex{*block.vtx.back()};
    BOOST_REQUIRE_EQUAL(hogex.vout.size(), 2U);
    hogex.vout[1].nValue += 1;
    ReplaceTransaction(block, block.vtx.size() - 1, std::move(hogex));

    ExpectContextualReject(block, BlockValidationResult::BLOCK_MUTATED, "bad-blk-mweb");
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(mweb_node_connect_tests, MWEBNodeTestingSetup)

// Connecting a valid pegin with a fee adds its MWEB output, advances the best header, and produces undo data.
BOOST_AUTO_TEST_CASE(ValidPeginUpdatesMWEBViewAndCreatesUndo)
{
    const test::Tx transaction = BuildPeginWithFee();
    const CBlock block = BuildBlock({transaction});
    CBlockUndo block_undo;
    BlockValidationState state;

    BOOST_REQUIRE_MESSAGE(
        MWEB::Node::ConnectBlock(
            block,
            ConsensusParams(),
            *Assert(m_node.chainman),
            &m_previous,
            block_undo,
            *m_view,
            state),
        state.ToString());

    BOOST_REQUIRE(block_undo.mwundo != nullptr);
    BOOST_REQUIRE(m_view->GetBestHeader() != nullptr);
    BOOST_CHECK(m_view->GetBestHeader()->GetHash() == block.mweb_block.GetHash());
    BOOST_CHECK(m_view->HasCoin(transaction.GetOutputs().front().GetOutputID()));
}

// Connecting fails when the first HogEx input points to a transaction other than the previous HogEx.
BOOST_AUTO_TEST_CASE(HogExMustSpendPreviousHogAddr)
{
    CBlock block = BuildBlock();
    CMutableTransaction hogex{*block.vtx.back()};
    hogex.vin.front().prevout.hash = uint256{2};
    ReplaceTransaction(block, block.vtx.size() - 1, std::move(hogex));

    ExpectConnectReject(block, BlockValidationResult::BLOCK_CONSENSUS, "invalid-hogex-input");
}

// Increasing the HogAddr amount reduces the HogEx fee below the MWEB fee, so connection is rejected.
BOOST_AUTO_TEST_CASE(HogExFeeMustMatchExtensionBlockFee)
{
    const test::Tx transaction = BuildPeginWithFee();
    CBlock block = BuildBlock({transaction});
    CMutableTransaction hogex{*block.vtx.back()};
    hogex.vout.front().nValue += 1;
    ReplaceTransaction(block, block.vtx.size() - 1, std::move(hogex));

    ExpectConnectReject(block, BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-mweb-fee-mismatch");
}

// Move one satoshi from a pegout to the HogAddr while preserving the total fee; the wrong MWEB balance is rejected.
BOOST_AUTO_TEST_CASE(HogAddrAmountMustMatchSupplyChange)
{
    const test::Tx transaction = BuildPeginAndPegout();
    CBlock block = BuildBlock({transaction});
    CMutableTransaction hogex{*block.vtx.back()};
    BOOST_REQUIRE_EQUAL(hogex.vout.size(), 2U);

    // Preserve GetValueOut(), and therefore the HogEx fee, while changing the
    // amount assigned to the MWEB HogAddr.
    hogex.vout.front().nValue += 1;
    hogex.vout[1].nValue -= 1;
    ReplaceTransaction(block, block.vtx.size() - 1, std::move(hogex));

    ExpectConnectReject(block, BlockValidationResult::BLOCK_CONSENSUS, "mweb-amount-mismatch");
}

// Pegins totaling MAX_MONEY plus one satoshi are rejected during connection's amount accounting.
BOOST_AUTO_TEST_CASE(AccumulatedPeginsMustStayInMoneyRange)
{
    CBlock block = BuildBlock();
    CMutableTransaction pegin_transaction;
    pegin_transaction.vout.emplace_back(MAX_MONEY, GetScriptForPegin(mw::Hash::ValueOf(1)));
    pegin_transaction.vout.emplace_back(1, GetScriptForPegin(mw::Hash::ValueOf(2)));
    block.vtx.insert(block.vtx.end() - 1, MakeTransactionRef(std::move(pegin_transaction)));

    ExpectConnectReject(block, BlockValidationResult::BLOCK_CONSENSUS, "accumulated-pegin-outofrange");
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(mweb_node_stateful_connect_tests, FundedMWEBNodeTestingSetup)

// Remove a funding coin before connecting its spend; the missing-UTXO error becomes a mutated-block rejection.
BOOST_AUTO_TEST_CASE(MissingMWEBInputIsReportedAsMutatedBlock)
{
    const test::Tx transaction = BuildSpendOfPreviousOutput();
    const CBlock block = BuildBlock({transaction});
    BOOST_REQUIRE(m_view->SpendCoin(m_funding_tx->GetOutputs().front().GetOutputID()) != nullptr);

    ExpectConnectReject(
        block,
        BlockValidationResult::BLOCK_MUTATED,
        "mweb-connect-failed-utxo-missing");
}

// Change the input's output public key so it no longer matches the stored coin; connection reports a UTXO mismatch.
BOOST_AUTO_TEST_CASE(MismatchedMWEBInputMetadataIsReportedAsMutatedBlock)
{
    const test::Tx transaction = BuildSpendOfPreviousOutput();
    CBlock block = BuildBlock({transaction});

    mw::MutableInput input{block.mweb_block.m_block->GetInputs().front().GetOutputID()};
    input.Update(block.mweb_block.m_block->GetInputs().front());
    input.output_pubkey = PublicKey::Random();
    BOOST_REQUIRE(input.Finalized().has_value());
    block.mweb_block = MWEB::Block{
        mw::MutBlock{block.mweb_block.m_block}
            .SetInputs({*input.Finalized()})
            .Build()};

    ExpectConnectReject(
        block,
        BlockValidationResult::BLOCK_MUTATED,
        "mweb-connect-failed-utxo-mismatch");
}

// Put the funding output on the frozen list; spending it causes a consensus rejection during connection.
BOOST_AUTO_TEST_CASE(FrozenMWEBOutputCannotBeSpent)
{
    const test::Tx transaction = BuildSpendOfPreviousOutput();
    const CBlock block = BuildBlock({transaction});
    Consensus::Params params = ConsensusParams();
    params.frozen_mweb_output_ids.push_back(
        uint256{m_funding_tx->GetOutputs().front().GetOutputID().vec()});

    ExpectConnectReject(
        block,
        BlockValidationResult::BLOCK_CONSENSUS,
        "frozen-mweb-output-spent",
        &params);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(mweb_node_transaction_tests, MWEBNodeTestingSetup)

// A hybrid transaction passes when its canonical pegin output matches the MWEB kernel's amount and ID.
BOOST_AUTO_TEST_CASE(MatchingHybridPeginPasses)
{
    const test::Tx mweb_transaction = test::Tx::CreatePegIn(PEGIN_AMOUNT);
    const PegInCoin pegin = mweb_transaction.GetPegInCoin();
    const CTransaction transaction{HybridPeginTransaction(
        mweb_transaction,
        pegin.GetAmount(),
        pegin.GetKernelID())};
    TxValidationState state;

    BOOST_CHECK_MESSAGE(MWEB::Node::CheckTransaction(transaction, state), state.ToString());
    BOOST_CHECK(state.IsValid());
}

// Two canonical outputs referencing the same pegin kernel are rejected as duplicate pegins.
BOOST_AUTO_TEST_CASE(DuplicateCanonicalPeginIsRejected)
{
    const test::Tx mweb_transaction = test::Tx::CreatePegIn(PEGIN_AMOUNT);
    const PegInCoin pegin = mweb_transaction.GetPegInCoin();
    CMutableTransaction mutable_transaction = HybridPeginTransaction(
        mweb_transaction,
        pegin.GetAmount(),
        pegin.GetKernelID());
    mutable_transaction.vout.push_back(mutable_transaction.vout.front());
    const CTransaction transaction{mutable_transaction};
    TxValidationState state;

    BOOST_CHECK(!MWEB::Node::CheckTransaction(transaction, state));
    BOOST_CHECK_EQUAL(state.GetResult(), TxValidationResult::TX_RECENT_CONSENSUS_CHANGE);
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "duplicate-tx-pegins");
}

// An MWEB pegin kernel without a corresponding canonical output is rejected as a witness mutation.
BOOST_AUTO_TEST_CASE(PeginCountMismatchIsWitnessMutation)
{
    const test::Tx mweb_transaction = test::Tx::CreatePegIn(PEGIN_AMOUNT);
    CMutableTransaction mutable_transaction;
    mutable_transaction.mweb_tx = mw::MutableTx::From(*mweb_transaction.GetTransaction());
    const CTransaction transaction{mutable_transaction};
    TxValidationState state;

    BOOST_CHECK(!MWEB::Node::CheckTransaction(transaction, state));
    BOOST_CHECK_EQUAL(state.GetResult(), TxValidationResult::TX_WITNESS_MUTATED);
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "pegin-count-mismatch");
}

// A canonical pegin amount one satoshi above the kernel's amount is rejected as a witness mutation.
BOOST_AUTO_TEST_CASE(PeginAmountMismatchIsWitnessMutation)
{
    const test::Tx mweb_transaction = test::Tx::CreatePegIn(PEGIN_AMOUNT);
    const PegInCoin pegin = mweb_transaction.GetPegInCoin();
    const CTransaction transaction{HybridPeginTransaction(
        mweb_transaction,
        pegin.GetAmount() + 1,
        pegin.GetKernelID())};
    TxValidationState state;

    BOOST_CHECK(!MWEB::Node::CheckTransaction(transaction, state));
    BOOST_CHECK_EQUAL(state.GetResult(), TxValidationResult::TX_WITNESS_MUTATED);
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "pegin-mismatch");
}

// A canonical pegin referencing the wrong kernel ID is rejected even when its amount matches.
BOOST_AUTO_TEST_CASE(PeginKernelMismatchIsWitnessMutation)
{
    const test::Tx mweb_transaction = test::Tx::CreatePegIn(PEGIN_AMOUNT);
    const PegInCoin pegin = mweb_transaction.GetPegInCoin();
    const CTransaction transaction{HybridPeginTransaction(
        mweb_transaction,
        pegin.GetAmount(),
        mw::Hash::ValueOf(1))};
    TxValidationState state;

    BOOST_CHECK(!MWEB::Node::CheckTransaction(transaction, state));
    BOOST_CHECK_EQUAL(state.GetResult(), TxValidationResult::TX_WITNESS_MUTATED);
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "pegin-mismatch");
}

// Changing an MWEB output's receiver public key invalidates its signature; the reject reason retains that error.
BOOST_AUTO_TEST_CASE(InvalidMWEBSignatureIncludesConsensusErrorInRejectReason)
{
    const test::Tx mweb_transaction = test::Tx::CreatePegIn(PEGIN_AMOUNT);
    const PegInCoin pegin = mweb_transaction.GetPegInCoin();
    CMutableTransaction mutable_transaction = HybridPeginTransaction(
        mweb_transaction,
        pegin.GetAmount(),
        pegin.GetKernelID());
    mutable_transaction.mweb_tx.outputs.front().receiver_pubkey = PublicKey::Random();
    const CTransaction transaction{mutable_transaction};
    TxValidationState state;

    BOOST_CHECK(!MWEB::Node::CheckTransaction(transaction, state));
    BOOST_CHECK_EQUAL(state.GetResult(), TxValidationResult::TX_WITNESS_MUTATED);
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-mweb-txn-invalid-sig");
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(mweb_node_activation_tests, MWEBActivationBoundaryTestingSetup)

// At the activation boundary, the first HogEx spends only the pegin and has no previous HogAddr input.
// The block passes contextual validation and connects its MWEB output successfully.
BOOST_AUTO_TEST_CASE(FirstHogExUsesOnlyPeginInputs)
{
    const test::Tx transaction = test::Tx::CreatePegIn(PEGIN_AMOUNT);
    const CBlock block = BuildFirstMWEBBlock({transaction});
    const CTransactionRef& pegin_transaction = block.vtx[1];
    const CTransactionRef& hogex = block.vtx.back();

    BOOST_REQUIRE_EQUAL(hogex->vin.size(), 1U);
    BOOST_CHECK(hogex->vin.front().prevout == COutPoint(pegin_transaction->GetHash(), 0));
    BOOST_CHECK(!DeploymentActiveAt(
        *PreviousBlock(),
        *Assert(m_node.chainman),
        Consensus::DEPLOYMENT_MWEB));
    BOOST_REQUIRE(DeploymentActiveAfter(
        PreviousBlock(),
        *Assert(m_node.chainman),
        Consensus::DEPLOYMENT_MWEB));

    BlockValidationState contextual_state;
    BOOST_REQUIRE_MESSAGE(
        MWEB::Node::ContextualCheckBlock(
            block,
            Assert(m_node.chainman)->GetConsensus(),
            *Assert(m_node.chainman),
            PreviousBlock(),
            contextual_state),
        contextual_state.ToString());

    CBlockUndo block_undo;
    BlockValidationState connect_state;
    BOOST_REQUIRE_MESSAGE(
        MWEB::Node::ConnectBlock(
            block,
            Assert(m_node.chainman)->GetConsensus(),
            *Assert(m_node.chainman),
            PreviousBlock(),
            block_undo,
            *m_view,
            connect_state),
        connect_state.ToString());
    BOOST_CHECK(m_view->HasCoin(transaction.GetOutputs().front().GetOutputID()));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(mweb_node_pre_activation_tests, InactiveMWEBNodeTestingSetup)

// Supplying an extension block before MWEB activation is rejected as mutated data.
BOOST_AUTO_TEST_CASE(ExtensionBlockBeforeActivationIsMutated)
{
    CBlock block;
    block.vtx.push_back(MakeCoinbase());
    block.mweb_block = MWEB::Block{m_miner.MineBlock(1).GetBlock()};
    BlockValidationState state;

    BOOST_CHECK(!MWEB::Node::ContextualCheckBlock(
        block,
        Assert(m_node.chainman)->GetConsensus(),
        *Assert(m_node.chainman),
        PreviousBlock(),
        state));
    BOOST_CHECK_EQUAL(state.GetResult(), BlockValidationResult::BLOCK_MUTATED);
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "unexpected-mweb-data");
}

// Supplying a HogEx marker before MWEB activation is rejected even without an extension block.
BOOST_AUTO_TEST_CASE(HogExMarkerBeforeActivationIsMutated)
{
    CBlock block;
    block.vtx.push_back(MakeCoinbase());
    CMutableTransaction hogex;
    hogex.m_hogEx = true;
    block.vtx.push_back(MakeTransactionRef(std::move(hogex)));
    BlockValidationState state;

    BOOST_CHECK(!MWEB::Node::ContextualCheckBlock(
        block,
        Assert(m_node.chainman)->GetConsensus(),
        *Assert(m_node.chainman),
        PreviousBlock(),
        state));
    BOOST_CHECK_EQUAL(state.GetResult(), BlockValidationResult::BLOCK_MUTATED);
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "unexpected-mweb-data");
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace
