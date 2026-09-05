// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <mw/consensus/Aggregation.h>
#include <mw/crypto/Blinds.h>
#include <mw/crypto/KeyDerivation.h>
#include <mw/crypto/PublicKeys.h>
#include <mw/models/tx/MutableTx.h>
#include <mw/node/CoinsView.h>
#include <policy/policy.h>
#include <script/standard.h>
#include <test/util/mining.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <util/time.h>
#include <validation.h>

#include <test_framework/TxBuilder.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr CAmount FUNDING_AMOUNT{10 * COIN};
constexpr CAmount MWEB_FEE{10'000};
constexpr CAmount CANONICAL_FEE{20'000};
constexpr int64_t TEST_TIME{1'601'450'001};
constexpr size_t ANCESTOR_LIMIT{5};

CMutableTransaction WithMWEB(const test::Tx& mweb_tx)
{
    CMutableTransaction tx;
    tx.mweb_tx = mw::MutableTx::From(*mweb_tx.GetTransaction());
    for (const PegInCoin& pegin : mweb_tx.GetPegIns()) {
        tx.vout.emplace_back(pegin.GetAmount(), GetScriptForPegin(pegin.GetKernelID()));
    }
    if (!tx.vout.empty()) {
        tx.vin.emplace_back(uint256{mweb_tx.GetTransaction()->GetHash().vec()}, 0);
        tx.vin.front().scriptWitness.stack = {WITNESS_STACK_ELEM_OP_TRUE};
    }
    return tx;
}

CTransactionRef CanonicalSpend(const COutPoint& input, const CAmount amount)
{
    CMutableTransaction tx;
    tx.vin.emplace_back(input);
    tx.vin.front().scriptWitness.stack = {WITNESS_STACK_ELEM_OP_TRUE};
    tx.vout.emplace_back(amount, P2WSH_OP_TRUE);
    return MakeTransactionRef(tx);
}

// Extra kernels are signed and their blinds are included in the offset, so
// feature and lock-height tests do not fail incidentally on invalid signatures.
test::Tx WithExtraKernel(const test::Tx& tx, const std::optional<int32_t> lock_height = std::nullopt,
                        const std::vector<uint8_t>& extra_data = {})
{
    const auto& original = tx.GetTransaction();
    const BlindingFactor blind = BlindingFactor::Random();
    auto kernels = original->GetKernels();
    kernels.push_back(mw::Kernel::Create(blind, std::nullopt, 0, std::nullopt, {}, lock_height, extra_data));
    return test::Tx{mw::Transaction::Create(
        Blinds(original->GetKernelOffset()).Sub(blind).Total(), original->GetStealthOffset(),
        original->GetInputs(), original->GetOutputs(), std::move(kernels)), tx.GetOutputs()};
}

/**
 * Exercise real admission with standardness, fees, signatures, and consistency
 * checks enabled. Only initial funding is seeded into chainstate. A small
 * ancestor limit keeps the boundary tests readable without long artificial chains.
 */
class MWEBMempoolTestingSetup : public TestingSetup
{
public:
    MWEBMempoolTestingSetup()
        : TestingSetup{CBaseChainParams::REGTEST, {
              "-acceptnonstdtxn=0", "-mempoolreplacement=0", "-limitancestorcount=5",
              "-vbparams=mweb:-1:9223372036854775807:0:0"}},
          m_pool{*m_node.mempool},
          m_coins{m_node.chainman->ActiveChainstate().CoinsTip()},
          m_view{m_coins.GetMWEBCacheView()},
          m_address{PublicKey::From(SecretKey::Random()), PublicKey::From(m_spend_key)}
    {
        SetMockTime(TEST_TIME);
        BOOST_REQUIRE(m_pool.m_require_standard);
        BOOST_REQUIRE_EQUAL(m_pool.m_limits.ancestor_count, ANCESTOR_LIMIT);
    }

    // Standard hybrid transactions carry their fee on the peg-in kernel itself.
    test::Tx Pegin(const CAmount amount = FUNDING_AMOUNT, const CAmount fee = MWEB_FEE) const
    {
        const test::TxOutput output = test::TxOutput::Create(m_sender_key, m_address, amount - fee);
        const BlindingFactor kernel_blind = BlindingFactor::Random();
        const auto kernel = mw::Kernel::Create(kernel_blind, std::nullopt, fee, amount, {}, std::nullopt, {});
        return test::Tx{mw::Transaction::Create(
            Blinds(output.GetBlind()).Sub(kernel_blind).Total(), m_sender_key,
            {}, {output.GetOutput()}, {kernel}), {output}};
    }

    SecretKey OutputKey(const test::TxOutput& output) const
    {
        return mw::DeriveOutputSpendKey(m_spend_key,
            mw::DeriveSharedSecret(m_sender_key, m_address, output.GetAmount()));
    }

    test::Tx Spend(const std::vector<test::TxOutput>& inputs, const CAmount fee = MWEB_FEE,
                   const std::vector<PegOutCoin>& pegouts = {}, const size_t num_outputs = 1) const
    {
        test::TxBuilder builder;
        CAmount change{-fee};
        for (const auto& input : inputs) {
            builder.AddInput(input.GetAmount(), OutputKey(input), input.GetBlind(), input.GetOutputID());
            change += input.GetAmount();
        }
        for (const auto& pegout : pegouts) change -= pegout.GetAmount();
        BOOST_REQUIRE_GT(change, 0);
        BOOST_REQUIRE_GT(num_outputs, 0U);
        const CAmount amount = change / num_outputs;
        for (size_t i = 0; i < num_outputs; ++i) {
            const CAmount output_amount = i + 1 == num_outputs ? change : amount;
            builder.AddOutput(output_amount, m_sender_key, m_address);
            change -= output_amount;
        }
        if (pegouts.empty()) {
            builder.AddPlainKernel(fee);
        } else {
            builder.AddPegoutKernel(pegouts, fee);
        }
        return builder.Build();
    }

    test::Tx Spend(const test::TxOutput& input, const CAmount fee = MWEB_FEE,
                   const std::vector<PegOutCoin>& pegouts = {}) const
    {
        return Spend(std::vector<test::TxOutput>{input}, fee, pegouts);
    }

    test::Tx FundMWEB()
    {
        LOCK(cs_main);
        const auto funding = Pegin(FUNDING_AMOUNT, 0);
        const auto block = mw::CoinsViewCache(m_view).BuildNextBlock(0, {funding.GetTransaction()});
        m_view->ApplyBlock(block);
        m_funded_amount += FUNDING_AMOUNT;
        return funding;
    }

    CTransactionRef FundPegin(const test::Tx& mweb_tx, const CAmount canonical_fee = CANONICAL_FEE,
                              const CAmount canonical_change = 0)
    {
        LOCK(cs_main);
        CMutableTransaction mutable_tx = WithMWEB(mweb_tx);
        if (canonical_change > 0) mutable_tx.vout.emplace_back(canonical_change, P2WSH_OP_TRUE);
        const auto tx = MakeTransactionRef(mutable_tx);
        BOOST_REQUIRE_EQUAL(tx->vin.size(), 1U);
        m_coins.AddCoin(tx->vin.front().prevout,
            Coin{CTxOut{tx->GetValueOut() + canonical_fee, P2WSH_OP_TRUE}, m_node.chainman->ActiveChain().Height(), false}, false);
        return tx;
    }

    MempoolAcceptResult Submit(const CTransactionRef& tx, const bool test_accept = false)
    {
        LOCK(cs_main);
        return m_node.chainman->ProcessTransaction(tx, test_accept);
    }

    void Accept(const CTransactionRef& tx, const CAmount fee = MWEB_FEE)
    {
        const auto result = Submit(tx);
        BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID, result.m_state.ToString());
        BOOST_REQUIRE(result.m_base_fees.has_value());
        BOOST_CHECK_EQUAL(*result.m_base_fees, fee);
        BOOST_REQUIRE(result.m_mweb_weight.has_value());
        BOOST_CHECK_EQUAL(*result.m_mweb_weight, tx->mweb_tx.GetMWEBWeight());
    }

    void Reject(const CTransactionRef& tx, const TxValidationResult error, const std::string& reason,
                const std::vector<CTransactionRef>& unchanged = {})
    {
        const auto result = Submit(tx);
        BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::INVALID, result.m_state.ToString());
        BOOST_CHECK(result.m_state.GetResult() == error);
        BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), reason);
        CheckPool(unchanged);
    }

    // Check exact membership and both MWEB indexes, not just the transaction
    // count. The built-in consistency checker also validates cached graph totals.
    void CheckPool(const std::vector<CTransactionRef>& expected)
    {
        LOCK2(cs_main, m_pool.cs);
        BOOST_REQUIRE_EQUAL(m_pool.size(), expected.size());
        std::map<AnyOutputID, const CTransaction*> spenders;
        std::map<mw::Hash, const CTransaction*> creators;
        for (const auto& tx : expected) {
            BOOST_CHECK(m_pool.get(tx->GetHash()) == tx);
            BOOST_CHECK(m_pool.exists(GenTxid::Wtxid(tx->GetWitnessHash())));
            for (const auto& input : tx->GetInputs()) spenders.emplace(input.GetID(), tx.get());
            for (const auto& output_id : tx->mweb_tx.GetOutputIDs()) creators.emplace(output_id, tx.get());
        }
        BOOST_CHECK(m_pool.mapTxOutputs_MWEB == creators);
        BOOST_REQUIRE_EQUAL(m_pool.mapNextTx.size(), spenders.size());
        for (const auto& [input, spender] : spenders) {
            BOOST_CHECK(m_pool.isSpent(input));
            BOOST_CHECK(m_pool.GetConflictTx(input) == spender);
        }
        m_pool.check(m_coins, m_node.chainman->ActiveChain().Height() + 1);
    }

    void CheckGraph(const CTransactionRef& tx, const std::vector<CTransactionRef>& ancestors,
                    const std::vector<CTransactionRef>& descendants)
    {
        LOCK(m_pool.cs);
        const auto entry = m_pool.mapTx.find(tx->GetHash());
        BOOST_REQUIRE(entry != m_pool.mapTx.end());
        BOOST_CHECK_EQUAL(entry->GetCountWithAncestors(), ancestors.size());
        BOOST_CHECK_EQUAL(entry->GetCountWithDescendants(), descendants.size());
        uint64_t ancestor_weight{0}, descendant_weight{0};
        CAmount ancestor_fees{0}, descendant_fees{0};
        for (const auto& ancestor : ancestors) {
            ancestor_weight += ancestor->mweb_tx.GetMWEBWeight();
            ancestor_fees += m_pool.mapTx.find(ancestor->GetHash())->GetModifiedFee();
        }
        for (const auto& descendant : descendants) {
            descendant_weight += descendant->mweb_tx.GetMWEBWeight();
            descendant_fees += m_pool.mapTx.find(descendant->GetHash())->GetModifiedFee();
        }
        BOOST_CHECK_EQUAL(entry->GetMWEBWeightWithAncestors(), ancestor_weight);
        BOOST_CHECK_EQUAL(entry->GetMWEBWeightWithDescendants(), descendant_weight);
        BOOST_CHECK_EQUAL(entry->GetModFeesWithAncestors(), ancestor_fees);
        BOOST_CHECK_EQUAL(entry->GetModFeesWithDescendants(), descendant_fees);
    }

    void Remove(const CTransactionRef& tx, const MemPoolRemovalReason reason = MemPoolRemovalReason::EXPIRY)
    {
        LOCK(m_pool.cs);
        m_pool.removeRecursive(*tx, reason);
    }

    // Apply coins and deliver the block fields consumed by removeForBlock.
    // Header/PoW/HogEx validation belongs to the node and miner suites.
    void Confirm(const std::vector<CTransactionRef>& transactions)
    {
        LOCK2(cs_main, m_pool.cs);
        CBlock block;
        std::vector<mw::Transaction::CPtr> mweb_transactions;
        for (const auto& tx : transactions) {
            BOOST_REQUIRE(tx->HasMWEBTx());
            mweb_transactions.push_back(tx->mweb_tx.m_transaction);
            if (!tx->IsMWEBOnly()) {
                CMutableTransaction stripped{*tx};
                stripped.mweb_tx.SetNull();
                block.vtx.push_back(MakeTransactionRef(stripped));
            }
        }
        const int height = m_view->GetBestHeader() ? m_view->GetBestHeader()->GetHeight() + 1 : 1;
        block.mweb_block = MWEB::Block{mw::CoinsViewCache(m_view).BuildNextBlock(height, mweb_transactions)};
        m_view->ApplyBlock(block.mweb_block.m_block);
        for (const auto& tx : block.vtx) UpdateCoins(*tx, m_coins, height);
        m_pool.removeForBlock(block, height, nullptr);
    }

    void CheckCached(const CTransactionRef& tx)
    {
        LOCK(m_pool.cs);
        for (const auto& kernel_id : tx->mweb_tx.GetKernelIDs()) {
            BOOST_REQUIRE(m_pool.recentTxsByKernel.Cached(kernel_id));
            BOOST_CHECK(m_pool.recentTxsByKernel.Get(kernel_id) == tx);
        }
    }

    // Give the synthetic funded state a HogAddr so reorg tests can mine and
    // invalidate real blocks through the public chainstate API.
    void PrepareMining()
    {
        {
            LOCK(cs_main);
            BOOST_REQUIRE_EQUAL(m_pool.size(), 0U);
            if (!m_view->GetBestHeader()) {
                m_view->ApplyBlock(mw::CoinsViewCache(m_view).BuildNextBlock(0, {}));
            }
            CBlockIndex* tip = m_node.chainman->ActiveChain().Tip();
            BOOST_REQUIRE_EQUAL(tip->nHeight, 0);
            tip->mweb_header = m_view->GetBestHeader();
            tip->hogex_hash = uint256::ONE;
            tip->mweb_amount = m_funded_amount;
            m_coins.AddCoin(COutPoint{tip->hogex_hash, 0},
                Coin{CTxOut{m_funded_amount, CScript() << OP_8 << tip->mweb_header->GetHash().vec()}, 0, false}, false);
        }
        // Keep this anchor block: height-zero canonical undo entries have legacy
        // metadata semantics and cannot restore the synthetic genesis HogAddr.
        MineBlock(m_node, P2WSH_OP_TRUE);
    }

    void InvalidateTip()
    {
        CBlockIndex* tip = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip());
        BlockValidationState state;
        BOOST_REQUIRE_MESSAGE(m_node.chainman->ActiveChainstate().InvalidateBlock(state, tip), state.ToString());
    }

    PackageMempoolAcceptResult SubmitPackage(const std::vector<CTransactionRef>& transactions, const bool test_accept = false)
    {
        LOCK(cs_main);
        return ProcessNewPackage(m_node.chainman->ActiveChainstate(), m_pool, transactions, test_accept);
    }

    CTxMemPool& m_pool;
    CCoinsViewCache& m_coins;
    mw::CoinsViewCache::Ptr m_view;
    SecretKey m_spend_key{SecretKey::Random()};
    SecretKey m_sender_key{SecretKey::Random()};
    StealthAddress m_address;
    CAmount m_funded_amount{0};
};

// Maturity depends on chain height, not MWEB activation. A few empty regtest
// blocks and a seeded HogEx output suffice to exercise admission and rollback.
struct PegoutMaturityTestingSetup : public TestingSetup
{
    PegoutMaturityTestingSetup()
        : TestingSetup{CBaseChainParams::REGTEST, {"-acceptnonstdtxn=0"}}
    {
        SetMockTime(TEST_TIME);
        for (int i = 0; i < PEGOUT_MATURITY - 2; ++i) MineBlock(m_node, P2WSH_OP_TRUE);
        LOCK(cs_main);
        m_node.chainman->ActiveChainstate().CoinsTip().AddCoin(m_pegout,
            Coin{CTxOut{FUNDING_AMOUNT, P2WSH_OP_TRUE}, 0, false, /*fPegoutIn=*/true}, false);
    }

    MempoolAcceptResult Submit(const CTransactionRef& tx)
    {
        LOCK(cs_main);
        return m_node.chainman->ProcessTransaction(tx);
    }

    COutPoint m_pegout{uint256::ONE, 0};
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(mweb_mempool_tests, MWEBMempoolTestingSetup)

// A standard peg-in records both fee components and indexes its MWEB output without adding it to chainstate.
BOOST_AUTO_TEST_CASE(admit_pegin_with_canonical_and_mweb_fees)
{
    const auto pegin = FundPegin(Pegin());
    Accept(pegin, CANONICAL_FEE + MWEB_FEE);
    CheckPool({pegin});
    LOCK(m_pool.cs);
    BOOST_CHECK_EQUAL(m_pool.GetTotalFee(), CANONICAL_FEE + MWEB_FEE);
    const auto output_id = *pegin->mweb_tx.GetOutputIDs().begin();
    uint256 creator;
    BOOST_REQUIRE(m_pool.GetCreatedTx(output_id, creator));
    BOOST_CHECK(creator == pegin->GetHash());
    BOOST_CHECK(!m_view->HasCoin(output_id));
}

// A pure MWEB transfer needs no canonical inputs or outputs and reserves its confirmed input in the mempool.
BOOST_AUTO_TEST_CASE(admit_transfer_of_confirmed_output)
{
    const auto funding = FundMWEB();
    const auto transfer = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front())));
    BOOST_REQUIRE(transfer->IsMWEBOnly());
    Accept(transfer);
    CheckPool({transfer});
    BOOST_CHECK(m_view->HasCoin(funding.GetOutputs().front().GetOutputID()));
}

// A peg-out is admitted as MWEB data; its destination is not yet a spendable canonical mempool output.
BOOST_AUTO_TEST_CASE(admit_pegout_with_mweb_change)
{
    const auto funding = FundMWEB();
    const auto pegout = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front(), MWEB_FEE,
        {{3 * COIN, P2WSH_OP_TRUE}})));
    Accept(pegout);
    CheckPool({pegout});
    BOOST_CHECK(pegout->vout.empty());
    LOCK(m_pool.cs);
    CCoinsViewMemPool view{&m_coins, m_pool};
    Coin coin;
    BOOST_CHECK(!view.GetCoin(COutPoint{pegout->GetHash(), 0}, coin));
}

// A missing parent rejects the child, but retrying after the peg-in is admitted succeeds and links the dependency.
BOOST_AUTO_TEST_CASE(retry_child_after_admitting_parent)
{
    const auto parent_mweb = Pegin();
    const auto parent = FundPegin(parent_mweb);
    const auto child = MakeTransactionRef(WithMWEB(Spend(parent_mweb.GetOutputs().front())));
    Reject(child, TxValidationResult::TX_MISSING_INPUTS, "bad-txns-inputs-missingorspent");
    Accept(parent, CANONICAL_FEE + MWEB_FEE);
    Accept(child);
    CheckPool({parent, child});
    CheckGraph(parent, {parent}, {parent, child});
    CheckGraph(child, {parent, child}, {child});
}

// Test-only admission validates the transaction and reports its fees, but reserves no inputs and creates no indexes.
BOOST_AUTO_TEST_CASE(test_accept_does_not_change_mempool_or_chainstate)
{
    const auto funding = FundMWEB();
    const auto transfer = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front())));
    const auto header = m_view->GetBestHeader();
    const auto leafset = m_view->GetLeafSet()->Root();
    const auto result = Submit(transfer, /*test_accept=*/true);
    BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID, result.m_state.ToString());
    BOOST_REQUIRE(result.m_base_fees.has_value());
    BOOST_CHECK_EQUAL(*result.m_base_fees, MWEB_FEE);
    CheckPool({});
    BOOST_CHECK(m_view->GetBestHeader() == header);
    BOOST_CHECK(m_view->GetLeafSet()->Root() == leafset);
    BOOST_CHECK(m_view->HasCoin(funding.GetOutputs().front().GetOutputID()));
    Accept(transfer);
    CheckPool({transfer});
}

// A duplicate submission is rejected without duplicating the transaction, fee total, or MWEB indexes.
BOOST_AUTO_TEST_CASE(duplicate_submission_preserves_existing_entry)
{
    const auto pegin = FundPegin(Pegin());
    Accept(pegin, CANONICAL_FEE + MWEB_FEE);
    Reject(pegin, TxValidationResult::TX_CONFLICT, "txn-already-in-mempool", {pegin});
}

// A conflicting MWEB spend cannot displace the accepted transaction or its child when replacement is disabled.
BOOST_AUTO_TEST_CASE(conflicting_spend_preserves_parent_and_child)
{
    const auto funding = FundMWEB();
    const auto first_mweb = Spend(funding.GetOutputs().front());
    const auto first = MakeTransactionRef(WithMWEB(first_mweb));
    const auto child = MakeTransactionRef(WithMWEB(Spend(first_mweb.GetOutputs().front())));
    const auto conflict = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front(), 10 * MWEB_FEE)));
    Accept(first);
    Accept(child);
    Reject(conflict, TxValidationResult::TX_MEMPOOL_POLICY, "txn-mempool-conflict", {first, child});
    CheckGraph(first, {first}, {first, child});
}

// A mismatched canonical peg-in amount is rejected without reserving its input, allowing the correct transaction later.
BOOST_AUTO_TEST_CASE(pegin_mismatch_does_not_poison_retry)
{
    const auto pegin = FundPegin(Pegin());
    CMutableTransaction invalid{*pegin};
    --invalid.vout.front().nValue;
    Reject(MakeTransactionRef(invalid), TxValidationResult::TX_WITNESS_MUTATED, "pegin-mismatch");
    Accept(pegin, CANONICAL_FEE + MWEB_FEE);
    CheckPool({pegin});
}

// A signed input using the wrong receiver key fails the UTXO metadata check, not signature validation.
BOOST_AUTO_TEST_CASE(input_receiver_key_must_match_confirmed_coin)
{
    const auto funding = FundMWEB();
    const auto& output = funding.GetOutputs().front();
    const auto wrong_key = test::TxBuilder()
        .AddInput(output.GetAmount(), SecretKey::Random(), output.GetBlind(), output.GetOutputID())
        .AddOutput(output.GetAmount() - MWEB_FEE).AddPlainKernel(MWEB_FEE).Build();
    BOOST_REQUIRE(!wrong_key.GetTransaction()->Validate());
    Reject(MakeTransactionRef(WithMWEB(wrong_key)), TxValidationResult::TX_CONSENSUS, "bad-txns-input-mismatch");
    const auto valid = MakeTransactionRef(WithMWEB(Spend(output)));
    Accept(valid);
    CheckPool({valid});
}

// A signed input committing to the wrong amount is rejected even if it names a real output and uses its receiver key.
BOOST_AUTO_TEST_CASE(input_commitment_must_match_confirmed_coin)
{
    const auto funding = FundMWEB();
    const auto& output = funding.GetOutputs().front();
    const auto wrong_amount = test::TxBuilder()
        .AddInput(output.GetAmount() + 1, OutputKey(output), output.GetBlind(), output.GetOutputID())
        .AddOutput(output.GetAmount() + 1 - MWEB_FEE).AddPlainKernel(MWEB_FEE).Build();
    BOOST_REQUIRE(!wrong_amount.GetTransaction()->Validate());
    Reject(MakeTransactionRef(WithMWEB(wrong_amount)), TxValidationResult::TX_CONSENSUS, "bad-txns-input-mismatch");
    const auto valid = MakeTransactionRef(WithMWEB(Spend(output)));
    Accept(valid);
    CheckPool({valid});
}

// The minimum relay fee includes MWEB weight even for a transaction with zero canonical virtual size.
BOOST_AUTO_TEST_CASE(mweb_relay_fee_boundary)
{
    const auto funding = FundMWEB();
    const auto probe = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front())));
    BOOST_REQUIRE_EQUAL(GetVirtualTransactionSize(*probe), 0);
    const CAmount minimum_fee = m_pool.m_min_relay_feerate.GetFee(0, probe->mweb_tx.GetMWEBWeight());
    const auto below = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front(), minimum_fee - 1)));
    Reject(below, TxValidationResult::TX_MEMPOOL_POLICY, "mempool min fee not met");
    const auto at_limit = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front(), minimum_fee)));
    Accept(at_limit, minimum_fee);
    CheckPool({at_limit});
}

// Peg-out destinations must satisfy canonical dust policy before the MWEB spend enters the mempool.
BOOST_AUTO_TEST_CASE(dust_pegout_is_rejected)
{
    const auto funding = FundMWEB();
    const auto dust = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front(), MWEB_FEE,
        {{1, P2WSH_OP_TRUE}})));
    Reject(dust, TxValidationResult::TX_NOT_STANDARD, "dust");
    const auto valid = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front(), MWEB_FEE,
        {{COIN, P2WSH_OP_TRUE}})));
    Accept(valid);
    CheckPool({valid});
}

// Consensus-valid extra kernel data remains nonstandard relay policy and must not leave mempool state behind.
BOOST_AUTO_TEST_CASE(nonstandard_kernel_features_are_rejected)
{
    const auto funding = FundMWEB();
    const auto extra_data = WithExtraKernel(Spend(funding.GetOutputs().front()), std::nullopt, {1});
    BOOST_REQUIRE(!extra_data.GetTransaction()->Validate());
    Reject(MakeTransactionRef(WithMWEB(extra_data)), TxValidationResult::TX_NOT_STANDARD, "non-standard-mweb-tx");
}

// A hybrid cannot carry unrelated aggregated kernels even when its signatures and peg-in amounts are valid.
BOOST_AUTO_TEST_CASE(hybrid_aggregation_is_not_standard)
{
    const auto aggregated = WithExtraKernel(Pegin());
    BOOST_REQUIRE(!aggregated.GetTransaction()->Validate());
    const auto pegin = FundPegin(aggregated);
    Reject(pegin, TxValidationResult::TX_NOT_STANDARD, "kernel-mismatch");
}

// An invalid output signature must not reserve the input or prevent resubmission of the original valid transfer.
BOOST_AUTO_TEST_CASE(invalid_signature_does_not_poison_retry)
{
    const auto funding = FundMWEB();
    const auto valid = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front())));
    CMutableTransaction invalid{*valid};
    invalid.mweb_tx.outputs.front().signature = Signature{};
    Reject(MakeTransactionRef(invalid), TxValidationResult::TX_WITNESS_MUTATED, "bad-mweb-txn-invalid-sig");
    Accept(valid);
    CheckPool({valid});
}

// MWEB kernel height locks are admitted at the next block's height, but rejected one block beyond it.
BOOST_AUTO_TEST_CASE(kernel_lock_height_boundary)
{
    const auto funding = FundMWEB();
    const auto transfer = Spend(funding.GetOutputs().front());
    const auto future = MakeTransactionRef(WithMWEB(WithExtraKernel(transfer, 2)));
    Reject(future, TxValidationResult::TX_PREMATURE_SPEND, "non-final");
    const auto next_block = MakeTransactionRef(WithMWEB(WithExtraKernel(transfer, 1)));
    Accept(next_block);
    CheckPool({next_block});
}

// A diamond-shaped MWEB graph counts its shared ancestor once and retains the other branch after recursive removal.
BOOST_AUTO_TEST_CASE(diamond_graph_tracks_shared_ancestors_and_branch_removal)
{
    const auto funding = FundMWEB();
    const auto parent_mweb = Spend({funding.GetOutputs().front()}, MWEB_FEE, {}, 2);
    const auto left_mweb = Spend(parent_mweb.GetOutputs()[0]);
    const auto right_mweb = Spend(parent_mweb.GetOutputs()[1]);
    const auto parent = MakeTransactionRef(WithMWEB(parent_mweb));
    const auto left = MakeTransactionRef(WithMWEB(left_mweb));
    const auto right = MakeTransactionRef(WithMWEB(right_mweb));
    const auto join = MakeTransactionRef(WithMWEB(Spend({left_mweb.GetOutputs()[0], right_mweb.GetOutputs()[0]})));
    Accept(parent);
    Accept(left);
    Accept(right);
    Accept(join);
    CheckPool({parent, left, right, join});
    CheckGraph(parent, {parent}, {parent, left, right, join});
    CheckGraph(left, {parent, left}, {left, join});
    CheckGraph(right, {parent, right}, {right, join});
    CheckGraph(join, {parent, left, right, join}, {join});

    Remove(left);
    CheckPool({parent, right});
    CheckGraph(parent, {parent}, {parent, right});
    CheckGraph(right, {parent, right}, {right});
}

// A hybrid parent can have both canonical and MWEB children; removing it recursively clears both kinds of dependency.
BOOST_AUTO_TEST_CASE(hybrid_parent_tracks_both_canonical_and_mweb_children)
{
    const auto parent_mweb = Pegin();
    const auto parent = FundPegin(parent_mweb, CANONICAL_FEE, COIN);
    const auto canonical_child = CanonicalSpend(COutPoint{parent->GetHash(), 1}, COIN - CANONICAL_FEE);
    const auto mweb_child = MakeTransactionRef(WithMWEB(Spend(parent_mweb.GetOutputs().front())));
    const auto independent = FundPegin(Pegin(2 * COIN));
    Accept(parent, CANONICAL_FEE + MWEB_FEE);
    Accept(canonical_child, CANONICAL_FEE);
    Accept(mweb_child);
    Accept(independent, CANONICAL_FEE + MWEB_FEE);
    CheckPool({parent, canonical_child, mweb_child, independent});
    CheckGraph(parent, {parent}, {parent, canonical_child, mweb_child});
    CheckGraph(canonical_child, {parent, canonical_child}, {canonical_child});
    CheckGraph(mweb_child, {parent, mweb_child}, {mweb_child});

    Remove(parent);
    CheckPool({independent});
    CheckGraph(independent, {independent}, {independent});
}

// The ancestor limit includes the initial peg-in and every MWEB dependency, including transactions with zero vsize.
BOOST_AUTO_TEST_CASE(mweb_chain_obeys_ancestor_limit)
{
    auto current = Pegin();
    std::vector<CTransactionRef> chain{FundPegin(current)};
    Accept(chain.front(), CANONICAL_FEE + MWEB_FEE);
    for (size_t i = 1; i < ANCESTOR_LIMIT; ++i) {
        current = Spend(current.GetOutputs().front());
        chain.push_back(MakeTransactionRef(WithMWEB(current)));
        Accept(chain.back());
    }
    CheckPool(chain);
    CheckGraph(chain.back(), chain, {chain.back()});
    const auto beyond_limit = MakeTransactionRef(WithMWEB(Spend(current.GetOutputs().front())));
    Reject(beyond_limit, TxValidationResult::TX_MEMPOOL_POLICY, "too-long-mempool-chain", chain);
}

// Prioritising an MWEB parent updates descendant ancestor-fees without changing the fees actually paid by the pool.
BOOST_AUTO_TEST_CASE(prioritisation_updates_mweb_ancestor_fees)
{
    const auto parent_mweb = Pegin();
    const auto parent = FundPegin(parent_mweb);
    const auto child = MakeTransactionRef(WithMWEB(Spend(parent_mweb.GetOutputs().front())));
    Accept(parent, CANONICAL_FEE + MWEB_FEE);
    Accept(child);
    m_pool.PrioritiseTransaction(parent->GetHash(), 50'000);
    CheckPool({parent, child});
    CheckGraph(parent, {parent}, {parent, child});
    CheckGraph(child, {parent, child}, {child});
    LOCK(m_pool.cs);
    BOOST_CHECK_EQUAL(m_pool.GetTotalFee(), CANONICAL_FEE + 2 * MWEB_FEE);
    BOOST_CHECK_EQUAL(m_pool.mapTx.find(child->GetHash())->GetModFeesWithAncestors(),
                      CANONICAL_FEE + 2 * MWEB_FEE + 50'000);
}

// The coins overlay hides spent MWEB outputs, exposes unspent outputs with their metadata, and reveals them after removal.
BOOST_AUTO_TEST_CASE(coins_overlay_tracks_mweb_spends_and_removal)
{
    const auto funding = FundMWEB();
    const auto parent_mweb = Spend(funding.GetOutputs().front());
    const auto parent = MakeTransactionRef(WithMWEB(parent_mweb));
    const auto child = MakeTransactionRef(WithMWEB(Spend(parent_mweb.GetOutputs().front())));
    Accept(parent);
    LOCK2(cs_main, m_pool.cs);
    CCoinsViewMemPool view{&m_coins, m_pool};
    mw::Coin::CPtr coin;
    const auto& parent_output = parent_mweb.GetOutputs().front();
    BOOST_CHECK(!view.HaveCoin(funding.GetOutputs().front().GetOutputID()));
    BOOST_REQUIRE(view.GetMWEBCoin(parent_output.GetOutputID(), coin));
    BOOST_CHECK(coin->IsInMempool());
    BOOST_CHECK(coin->GetCommitment() == parent_output.GetCommitment());
    BOOST_CHECK(coin->GetReceiverPubKey() == parent_output.GetOutput().GetReceiverPubKey());

    Accept(child);
    BOOST_CHECK(!view.HaveCoin(parent_output.GetOutputID()));
    BOOST_CHECK(!view.GetMWEBCoin(parent_output.GetOutputID(), coin));
    Remove(child);
    BOOST_CHECK(view.HaveCoin(parent_output.GetOutputID()));
    BOOST_CHECK(view.GetMWEBCoin(parent_output.GetOutputID(), coin));
    CheckPool({parent});
}

// Expiring an old MWEB parent also removes its newer child, while an unrelated recent transaction remains.
BOOST_AUTO_TEST_CASE(expiration_removes_mweb_descendants)
{
    const auto parent_mweb = Pegin();
    const auto parent = FundPegin(parent_mweb);
    Accept(parent, CANONICAL_FEE + MWEB_FEE);
    SetMockTime(TEST_TIME + 60);
    const auto child = MakeTransactionRef(WithMWEB(Spend(parent_mweb.GetOutputs().front())));
    const auto independent = FundPegin(Pegin(2 * COIN));
    Accept(child);
    Accept(independent, CANONICAL_FEE + MWEB_FEE);
    LOCK2(cs_main, m_pool.cs);
    BOOST_CHECK_EQUAL(m_pool.Expire(std::chrono::seconds{TEST_TIME + 1}), 2);
    CheckPool({independent});
    for (const auto& id : parent->mweb_tx.GetKernelIDs()) BOOST_CHECK(!m_pool.recentTxsByKernel.Cached(id));
}

// Clearing a pool with MWEB dependencies removes every creator/spender index and permits the same transactions again.
BOOST_AUTO_TEST_CASE(clear_allows_clean_readmission)
{
    const auto parent_mweb = Pegin();
    const auto parent = FundPegin(parent_mweb);
    const auto child = MakeTransactionRef(WithMWEB(Spend(parent_mweb.GetOutputs().front())));
    Accept(parent, CANONICAL_FEE + MWEB_FEE);
    Accept(child);
    m_pool.clear();
    CheckPool({});
    Accept(parent, CANONICAL_FEE + MWEB_FEE);
    Accept(child);
    CheckPool({parent, child});
    CheckGraph(child, {parent, child}, {child});
}

// Mining a pure MWEB parent removes it by kernel ID, preserves its child, and resets the child's ancestor totals.
BOOST_AUTO_TEST_CASE(mined_parent_leaves_unmined_child)
{
    const auto funding = FundMWEB();
    const auto parent_mweb = Spend(funding.GetOutputs().front());
    const auto parent = MakeTransactionRef(WithMWEB(parent_mweb));
    const auto child = MakeTransactionRef(WithMWEB(Spend(parent_mweb.GetOutputs().front())));
    Accept(parent);
    Accept(child);
    Confirm({parent});
    CheckPool({child});
    CheckGraph(child, {child}, {child});
    CheckCached(parent);
    BOOST_CHECK(m_view->HasCoin(parent_mweb.GetOutputs().front().GetOutputID()));
}

// A mined hybrid arrives stripped of MWEB data, but removal caches the full original transaction for a later reorg.
BOOST_AUTO_TEST_CASE(mined_hybrid_caches_full_transaction)
{
    const auto parent_mweb = Pegin();
    const auto parent = FundPegin(parent_mweb);
    const auto child = MakeTransactionRef(WithMWEB(Spend(parent_mweb.GetOutputs().front())));
    Accept(parent, CANONICAL_FEE + MWEB_FEE);
    Accept(child);
    Confirm({parent});
    CheckPool({child});
    CheckGraph(child, {child}, {child});
    CheckCached(parent);
}

// All kernels of an aggregated pure-MWEB transaction identify the same full transaction in the reorg cache.
BOOST_AUTO_TEST_CASE(mined_aggregate_is_cached_under_every_kernel)
{
    const auto first_funding = FundMWEB();
    const auto second_funding = FundMWEB();
    const auto first = Spend(first_funding.GetOutputs().front());
    const auto second = Spend(second_funding.GetOutputs().front());
    const test::Tx combined{Aggregation::Aggregate({first.GetTransaction(), second.GetTransaction()}), {}};
    const auto aggregated = MakeTransactionRef(WithMWEB(combined));
    BOOST_REQUIRE_EQUAL(aggregated->mweb_tx.GetKernelIDs().size(), 2U);
    Accept(aggregated, 2 * MWEB_FEE);
    Confirm({aggregated});
    CheckPool({});
    CheckCached(aggregated);
}

// An unseen block transaction spending an MWEB input evicts the mempool conflict and its descendants by output ID.
BOOST_AUTO_TEST_CASE(mined_conflict_removes_mweb_descendants)
{
    const auto funding = FundMWEB();
    const auto loser_mweb = Spend(funding.GetOutputs().front());
    const auto loser = MakeTransactionRef(WithMWEB(loser_mweb));
    const auto child = MakeTransactionRef(WithMWEB(Spend(loser_mweb.GetOutputs().front())));
    const auto winner = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front(), 2 * MWEB_FEE)));
    const auto independent = FundPegin(Pegin(2 * COIN));
    Accept(loser);
    Accept(child);
    Accept(independent, CANONICAL_FEE + MWEB_FEE);
    Confirm({winner});
    CheckPool({independent});
    LOCK(m_pool.cs);
    for (const auto& id : loser->mweb_tx.GetKernelIDs()) BOOST_CHECK(!m_pool.recentTxsByKernel.Cached(id));
}

// Removing a parent no longer in the pool still finds and recursively removes its MWEB children.
BOOST_AUTO_TEST_CASE(remove_absent_parent_finds_mweb_descendants)
{
    const auto funding = FundMWEB();
    const auto parent_mweb = Spend(funding.GetOutputs().front());
    const auto parent = MakeTransactionRef(WithMWEB(parent_mweb));
    Accept(parent);
    Confirm({parent});
    const auto child_mweb = Spend(parent_mweb.GetOutputs().front());
    const auto child = MakeTransactionRef(WithMWEB(child_mweb));
    const auto grandchild = MakeTransactionRef(WithMWEB(Spend(child_mweb.GetOutputs().front())));
    Accept(child);
    Accept(grandchild);
    Remove(parent, MemPoolRemovalReason::REORG);
    CheckPool({});
}

// Disconnecting a mined MWEB parent restores its cached transaction and reattaches an already-unconfirmed child.
BOOST_AUTO_TEST_CASE(reorg_restores_parent_and_relinks_child)
{
    const auto funding = FundMWEB();
    PrepareMining();
    const auto parent_mweb = Spend(funding.GetOutputs().front());
    const auto parent = MakeTransactionRef(WithMWEB(parent_mweb));
    Accept(parent);
    MineBlock(m_node, P2WSH_OP_TRUE);
    CheckPool({});
    CheckCached(parent);
    const auto child = MakeTransactionRef(WithMWEB(Spend(parent_mweb.GetOutputs().front())));
    Accept(child);
    CheckGraph(child, {child}, {child});

    InvalidateTip();
    CheckPool({parent, child});
    CheckGraph(parent, {parent}, {parent, child});
    CheckGraph(child, {parent, child}, {child});
}

// A disconnected block's MWEB parent and child must both return, even when kernel order visits the child first.
BOOST_AUTO_TEST_CASE(reorg_restores_mined_parent_child_package)
{
    const auto funding = FundMWEB();
    PrepareMining();
    auto parent_mweb = Spend(funding.GetOutputs().front());
    auto child_mweb = Spend(parent_mweb.GetOutputs().front());
    // Reverse kernel traversal must encounter the child first. Choose that
    // ordering explicitly so this regression does not depend on random hashes.
    while (child_mweb.GetKernels().front().GetKernelID() < parent_mweb.GetKernels().front().GetKernelID()) {
        parent_mweb = Spend(funding.GetOutputs().front());
        child_mweb = Spend(parent_mweb.GetOutputs().front());
    }
    const auto parent = MakeTransactionRef(WithMWEB(parent_mweb));
    const auto child = MakeTransactionRef(WithMWEB(child_mweb));
    Accept(parent);
    Accept(child);
    MineBlock(m_node, P2WSH_OP_TRUE);
    CheckPool({});
    CheckCached(parent);
    CheckCached(child);
    InvalidateTip();
    BOOST_REQUIRE(m_pool.get(parent->GetHash()) == parent);
    CheckPool({parent, child});
    CheckGraph(parent, {parent}, {parent, child});
    CheckGraph(child, {parent, child}, {child});
}

// Restoring a mined hybrid must precede both its canonical change spender and its MWEB child.
BOOST_AUTO_TEST_CASE(reorg_restores_hybrid_with_both_kinds_of_children)
{
    PrepareMining();
    const auto parent_mweb = Pegin();
    const auto parent = FundPegin(parent_mweb, CANONICAL_FEE, COIN);
    const auto canonical_child = CanonicalSpend(COutPoint{parent->GetHash(), 1}, COIN - CANONICAL_FEE);
    const auto mweb_child = MakeTransactionRef(WithMWEB(Spend(parent_mweb.GetOutputs().front())));
    Accept(parent, CANONICAL_FEE + MWEB_FEE);
    Accept(canonical_child, CANONICAL_FEE);
    Accept(mweb_child);
    MineBlock(m_node, P2WSH_OP_TRUE);
    CheckPool({});
    CheckCached(parent);
    CheckCached(mweb_child);

    InvalidateTip();
    // Canonical transactions are read back from disk; the MWEB originals come from the cache.
    const auto restored_canonical_child = m_pool.get(canonical_child->GetHash());
    BOOST_REQUIRE(restored_canonical_child);
    BOOST_CHECK(restored_canonical_child->GetWitnessHash() == canonical_child->GetWitnessHash());
    CheckPool({parent, restored_canonical_child, mweb_child});
    CheckGraph(parent, {parent}, {parent, canonical_child, mweb_child});
    CheckGraph(canonical_child, {parent, canonical_child}, {canonical_child});
    CheckGraph(mweb_child, {parent, mweb_child}, {mweb_child});
}

// A mined diamond is restored once per transaction, even when its shared ancestor is cached under multiple kernels.
BOOST_AUTO_TEST_CASE(reorg_restores_diamond_with_multikernel_parent)
{
    const auto funding = FundMWEB();
    PrepareMining();
    const auto root_mweb = WithExtraKernel(Spend({funding.GetOutputs().front()}, MWEB_FEE, {}, 2));
    const auto left_mweb = Spend(root_mweb.GetOutputs()[0]);
    const auto right_mweb = Spend(root_mweb.GetOutputs()[1]);
    const auto root = MakeTransactionRef(WithMWEB(root_mweb));
    const auto left = MakeTransactionRef(WithMWEB(left_mweb));
    const auto right = MakeTransactionRef(WithMWEB(right_mweb));
    const auto join = MakeTransactionRef(WithMWEB(Spend({left_mweb.GetOutputs().front(), right_mweb.GetOutputs().front()})));
    Accept(root);
    Accept(left);
    Accept(right);
    Accept(join);
    MineBlock(m_node, P2WSH_OP_TRUE);
    CheckPool({});
    CheckCached(root);
    CheckCached(left);
    CheckCached(right);
    CheckCached(join);

    InvalidateTip();
    CheckPool({root, left, right, join});
    CheckGraph(root, {root}, {root, left, right, join});
    CheckGraph(left, {root, left}, {left, join});
    CheckGraph(right, {root, right}, {right, join});
    CheckGraph(join, {root, left, right, join}, {join});
}

// Spending two outputs of one aggregate does not cause the shared parent to be restored more than once.
BOOST_AUTO_TEST_CASE(reorg_restores_aggregate_with_multiple_outputs_spent_by_child)
{
    const auto first_funding = FundMWEB();
    const auto second_funding = FundMWEB();
    PrepareMining();
    const auto first = Spend(first_funding.GetOutputs().front());
    const auto second = Spend(second_funding.GetOutputs().front());
    const test::Tx aggregate_mweb{Aggregation::Aggregate({first.GetTransaction(), second.GetTransaction()}), {}};
    const auto aggregate = MakeTransactionRef(WithMWEB(aggregate_mweb));
    const auto child = MakeTransactionRef(WithMWEB(Spend({first.GetOutputs().front(), second.GetOutputs().front()})));
    Accept(aggregate, 2 * MWEB_FEE);
    Accept(child);
    MineBlock(m_node, P2WSH_OP_TRUE);
    CheckPool({});
    CheckCached(aggregate);
    CheckCached(child);

    InvalidateTip();
    CheckPool({aggregate, child});
    CheckGraph(aggregate, {aggregate}, {aggregate, child});
    CheckGraph(child, {aggregate, child}, {child});
}

// Disconnecting several blocks restores all MWEB ancestors and repairs the surviving descendant links.
BOOST_AUTO_TEST_CASE(reorg_restores_dependencies_across_disconnected_blocks)
{
    const auto funding = FundMWEB();
    PrepareMining();
    const auto parent_mweb = Spend(funding.GetOutputs().front());
    const auto parent = MakeTransactionRef(WithMWEB(parent_mweb));
    Accept(parent);
    MineBlock(m_node, P2WSH_OP_TRUE);
    CBlockIndex* parent_block = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip());
    const auto child_mweb = Spend(parent_mweb.GetOutputs().front());
    const auto child = MakeTransactionRef(WithMWEB(child_mweb));
    const auto grandchild = MakeTransactionRef(WithMWEB(Spend(child_mweb.GetOutputs().front())));
    Accept(child);
    Accept(grandchild);
    MineBlock(m_node, P2WSH_OP_TRUE);
    CheckPool({});
    CheckCached(parent);
    CheckCached(child);
    CheckCached(grandchild);

    BlockValidationState state;
    BOOST_REQUIRE_MESSAGE(m_node.chainman->ActiveChainstate().InvalidateBlock(state, parent_block), state.ToString());
    CheckPool({parent, child, grandchild});
    CheckGraph(parent, {parent}, {parent, child, grandchild});
    CheckGraph(child, {parent, child}, {child, grandchild});
    CheckGraph(grandchild, {parent, child, grandchild}, {grandchild});
}

// A disconnected hybrid is resurrected with its MWEB data intact, rather than the stripped transaction stored in the block.
BOOST_AUTO_TEST_CASE(reorg_restores_full_hybrid_transaction)
{
    PrepareMining();
    const auto pegin = FundPegin(Pegin());
    Accept(pegin, CANONICAL_FEE + MWEB_FEE);
    MineBlock(m_node, P2WSH_OP_TRUE);
    CheckPool({});
    CheckCached(pegin);
    InvalidateTip();
    CheckPool({pegin});
    BOOST_REQUIRE(m_pool.get(pegin->GetHash())->HasMWEBTx());
    BOOST_CHECK(m_pool.get(pegin->GetHash())->GetWitnessHash() == pegin->GetWitnessHash());
}

// Rolling back the tip removes a now-height-locked MWEB child and its descendant, while restoring the valid parent.
BOOST_AUTO_TEST_CASE(reorg_removes_newly_nonfinal_mweb_descendants)
{
    const auto funding = FundMWEB();
    PrepareMining();
    const auto parent_mweb = Spend(funding.GetOutputs().front());
    const auto parent = MakeTransactionRef(WithMWEB(parent_mweb));
    Accept(parent);
    MineBlock(m_node, P2WSH_OP_TRUE);
    const auto child_mweb = WithExtraKernel(Spend(parent_mweb.GetOutputs().front()), 3);
    const auto child = MakeTransactionRef(WithMWEB(child_mweb));
    const auto grandchild = MakeTransactionRef(WithMWEB(Spend(child_mweb.GetOutputs().front())));
    Accept(child);
    Accept(grandchild);
    InvalidateTip();
    CheckPool({parent});
    CheckGraph(parent, {parent}, {parent});
}

// If the original mined transaction is no longer cached, a disconnect cannot resurrect it and must remove its orphaned children.
BOOST_AUTO_TEST_CASE(reorg_cache_miss_removes_orphaned_mweb_descendants)
{
    const auto funding = FundMWEB();
    PrepareMining();
    const auto parent_mweb = Spend(funding.GetOutputs().front());
    const auto parent = MakeTransactionRef(WithMWEB(parent_mweb));
    Accept(parent);
    MineBlock(m_node, P2WSH_OP_TRUE);
    const auto child_mweb = Spend(parent_mweb.GetOutputs().front());
    const auto child = MakeTransactionRef(WithMWEB(child_mweb));
    const auto grandchild = MakeTransactionRef(WithMWEB(Spend(child_mweb.GetOutputs().front())));
    Accept(child);
    Accept(grandchild);
    WITH_LOCK(m_pool.cs, m_pool.recentTxsByKernel.Clear());
    InvalidateTip();
    CheckPool({});
    BOOST_CHECK(m_view->HasCoin(funding.GetOutputs().front().GetOutputID()));
    BOOST_CHECK(!m_view->HasCoin(parent_mweb.GetOutputs().front().GetOutputID()));
}

// A standard transaction at the relay weight limit is accepted; adding another valid kernel makes it too large.
BOOST_AUTO_TEST_CASE(standard_mweb_weight_limit_is_inclusive)
{
    const auto funding = FundMWEB();
    const size_t weight_limit = mw::MAX_BLOCK_WEIGHT / 50;
    const size_t num_outputs = (weight_limit - 2 * mw::BASE_KERNEL_WEIGHT) / mw::STANDARD_OUTPUT_WEIGHT;
    const auto at_limit_mweb = WithExtraKernel(Spend({funding.GetOutputs().front()}, COIN, {}, num_outputs));
    BOOST_REQUIRE_EQUAL(at_limit_mweb.GetTransaction()->CalcWeight(), weight_limit);
    const auto oversized = WithExtraKernel(at_limit_mweb);
    BOOST_REQUIRE(!oversized.GetTransaction()->Validate());
    Reject(MakeTransactionRef(WithMWEB(oversized)), TxValidationResult::TX_NOT_STANDARD, "mweb-txn-oversize");
    const auto at_limit = MakeTransactionRef(WithMWEB(at_limit_mweb));
    Accept(at_limit, COIN);
    CheckPool({at_limit});
}

// At the input-count limit an otherwise valid transaction reaches coin lookup; one extra input is rejected by relay policy first.
BOOST_AUTO_TEST_CASE(standard_mweb_input_count_boundary)
{
    const size_t input_limit = mw::MAX_NUM_INPUTS / 50;
    const auto unfunded_spend = [](const size_t num_inputs) {
        test::TxBuilder builder;
        for (size_t i = 0; i < num_inputs; ++i) builder.AddInput(COIN);
        return builder.AddOutput((num_inputs - 1) * COIN).AddPlainKernel(COIN).Build();
    };
    const auto at_limit = unfunded_spend(input_limit);
    BOOST_REQUIRE(!at_limit.GetTransaction()->Validate());
    Reject(MakeTransactionRef(WithMWEB(at_limit)), TxValidationResult::TX_MISSING_INPUTS, "bad-txns-inputs-missingorspent");
    const auto oversized = unfunded_spend(input_limit + 1);
    Reject(MakeTransactionRef(WithMWEB(oversized)), TxValidationResult::TX_NOT_STANDARD, "mweb-txn-too-many-inputs");
}

// Memory pressure evicts a low-fee peg-in and its MWEB child together, retaining the higher-fee independent transaction.
BOOST_AUTO_TEST_CASE(size_trimming_removes_mweb_package)
{
    const auto parent_mweb = Pegin();
    const auto parent = FundPegin(parent_mweb);
    const auto child = MakeTransactionRef(WithMWEB(Spend(parent_mweb.GetOutputs().front())));
    const auto high_fee = FundPegin(Pegin(2 * COIN), COIN);
    Accept(parent, CANONICAL_FEE + MWEB_FEE);
    Accept(child);
    Accept(high_fee, COIN + MWEB_FEE);
    LOCK2(cs_main, m_pool.cs);
    std::vector<COutPoint> unspent_inputs;
    m_pool.TrimToSize(m_pool.DynamicMemoryUsage() - 1, &unspent_inputs);
    CheckPool({high_fee});
    CheckGraph(high_fee, {high_fee}, {high_fee});
    BOOST_REQUIRE_EQUAL(unspent_inputs.size(), 1U);
    BOOST_CHECK(unspent_inputs.front() == parent->vin.front().prevout);
}

// A canonical spend of a HogEx peg-out is rejected one block before maturity and accepted exactly at the boundary.
BOOST_FIXTURE_TEST_CASE(pegout_maturity_boundary, PegoutMaturityTestingSetup)
{
    const auto spend = CanonicalSpend(m_pegout, FUNDING_AMOUNT - CANONICAL_FEE);
    const auto immature = Submit(spend);
    BOOST_CHECK(immature.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(immature.m_state.GetResult() == TxValidationResult::TX_PREMATURE_SPEND);
    BOOST_CHECK_EQUAL(immature.m_state.GetRejectReason(), "bad-txns-premature-spend-of-pegout");
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);
    MineBlock(m_node, P2WSH_OP_TRUE);
    const auto mature = Submit(spend);
    BOOST_REQUIRE_MESSAGE(mature.m_result_type == MempoolAcceptResult::ResultType::VALID, mature.m_state.ToString());
    LOCK(m_node.mempool->cs);
    BOOST_CHECK(m_node.mempool->mapTx.find(spend->GetHash())->GetSpendsCoinbaseOrPegout());
}

// A real tip rollback makes a previously mature peg-out spend immature again and removes its canonical descendants.
BOOST_FIXTURE_TEST_CASE(reorg_removes_newly_immature_pegout_spend, PegoutMaturityTestingSetup)
{
    MineBlock(m_node, P2WSH_OP_TRUE);
    const auto parent = CanonicalSpend(m_pegout, FUNDING_AMOUNT - CANONICAL_FEE);
    const auto child = CanonicalSpend(COutPoint{parent->GetHash(), 0}, FUNDING_AMOUNT - 2 * CANONICAL_FEE);
    const auto parent_result = Submit(parent);
    BOOST_REQUIRE_MESSAGE(parent_result.m_result_type == MempoolAcceptResult::ResultType::VALID, parent_result.m_state.ToString());
    const auto child_result = Submit(child);
    BOOST_REQUIRE_MESSAGE(child_result.m_result_type == MempoolAcceptResult::ResultType::VALID, child_result.m_state.ToString());
    CBlockIndex* tip = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip());
    BlockValidationState state;
    BOOST_REQUIRE_MESSAGE(m_node.chainman->ActiveChainstate().InvalidateBlock(state, tip), state.ToString());
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);
    LOCK2(cs_main, m_node.mempool->cs);
    BOOST_CHECK(m_node.mempool->mapNextTx.empty());
    m_node.mempool->check(m_node.chainman->ActiveChainstate().CoinsTip(), PEGOUT_MATURITY - 1);
}

// A package dry run resolves the parent's temporary MWEB output, but that output is unavailable outside the package.
BOOST_AUTO_TEST_CASE(package_dry_run_does_not_leak_mweb_outputs)
{
    const auto parent_mweb = Pegin();
    const auto parent = FundPegin(parent_mweb);
    const auto child = MakeTransactionRef(WithMWEB(Spend(parent_mweb.GetOutputs().front())));
    const auto result = SubmitPackage({parent, child}, /*test_accept=*/true);
    BOOST_REQUIRE_MESSAGE(result.m_state.IsValid(), result.m_state.ToString());
    BOOST_REQUIRE_EQUAL(result.m_tx_results.size(), 2U);
    BOOST_CHECK(result.m_tx_results.at(parent->GetWitnessHash()).m_result_type == MempoolAcceptResult::ResultType::VALID);
    BOOST_CHECK(result.m_tx_results.at(child->GetWitnessHash()).m_result_type == MempoolAcceptResult::ResultType::VALID);
    CheckPool({});
    BOOST_CHECK(!m_view->HasCoin(parent_mweb.GetOutputs().front().GetOutputID()));
    Reject(child, TxValidationResult::TX_MISSING_INPUTS, "bad-txns-inputs-missingorspent");
    const auto submitted = SubmitPackage({parent, child});
    BOOST_REQUIRE_MESSAGE(submitted.m_state.IsValid(), submitted.m_state.ToString());
    CheckPool({parent, child});
}

// A fee-paying MWEB child can bring a zero-fee canonical peg-in parent into the mempool as one package.
BOOST_AUTO_TEST_CASE(package_child_pays_for_pegin_parent)
{
    const auto parent_mweb = Pegin(FUNDING_AMOUNT, 0);
    const auto parent = FundPegin(parent_mweb, 0);
    const auto child = MakeTransactionRef(WithMWEB(Spend(parent_mweb.GetOutputs().front())));
    Reject(parent, TxValidationResult::TX_MEMPOOL_POLICY, "mempool min fee not met");
    const auto result = SubmitPackage({parent, child});
    BOOST_REQUIRE_MESSAGE(result.m_state.IsValid(), result.m_state.ToString());
    BOOST_REQUIRE_EQUAL(result.m_tx_results.size(), 2U);
    BOOST_REQUIRE(result.m_tx_results.at(parent->GetWitnessHash()).m_base_fees.has_value());
    BOOST_CHECK_EQUAL(*result.m_tx_results.at(parent->GetWitnessHash()).m_base_fees, 0);
    BOOST_REQUIRE(result.m_tx_results.at(child->GetWitnessHash()).m_base_fees.has_value());
    BOOST_CHECK_EQUAL(*result.m_tx_results.at(child->GetWitnessHash()).m_base_fees, MWEB_FEE);
    CheckPool({parent, child});
    CheckGraph(child, {parent, child}, {child});
}

// Package fee accounting also works when both parent and child are pure MWEB transactions with zero canonical vsize.
BOOST_AUTO_TEST_CASE(package_child_pays_for_pure_mweb_parent)
{
    const auto funding = FundMWEB();
    const auto parent_mweb = Spend(funding.GetOutputs().front(), 0);
    const auto parent = MakeTransactionRef(WithMWEB(parent_mweb));
    const auto child = MakeTransactionRef(WithMWEB(Spend(parent_mweb.GetOutputs().front())));
    BOOST_REQUIRE_EQUAL(GetVirtualTransactionSize(*parent) + GetVirtualTransactionSize(*child), 0);
    Reject(parent, TxValidationResult::TX_MEMPOOL_POLICY, "mempool min fee not met");
    const auto result = SubmitPackage({parent, child});
    BOOST_REQUIRE_MESSAGE(result.m_state.IsValid(), result.m_state.ToString());
    CheckPool({parent, child});
    CheckGraph(child, {parent, child}, {child});
    LOCK(m_pool.cs);
    BOOST_CHECK_EQUAL(m_pool.GetTotalFee(), MWEB_FEE);
}

// A package whose total fee is below the MWEB weight charge admits neither its unpaid parent nor its child.
BOOST_AUTO_TEST_CASE(package_mweb_fee_shortfall_is_rejected)
{
    const auto funding = FundMWEB();
    const auto parent_mweb = Spend(funding.GetOutputs().front(), 0);
    const auto parent = MakeTransactionRef(WithMWEB(parent_mweb));
    const auto child = MakeTransactionRef(WithMWEB(Spend(parent_mweb.GetOutputs().front(), 1)));
    const auto result = SubmitPackage({parent, child});
    BOOST_CHECK(result.m_state.GetResult() == PackageValidationResult::PCKG_POLICY);
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "package-fee-too-low");
    CheckPool({});
}

// A joining transaction can spend MWEB outputs from two package parents, with both ancestors accounted for once.
BOOST_AUTO_TEST_CASE(package_resolves_multiple_mweb_parents)
{
    const auto first_mweb = Pegin(2 * COIN);
    const auto second_mweb = Pegin(3 * COIN);
    const auto first = FundPegin(first_mweb);
    const auto second = FundPegin(second_mweb);
    const auto child = MakeTransactionRef(WithMWEB(Spend({first_mweb.GetOutputs()[0], second_mweb.GetOutputs()[0]})));
    const auto result = SubmitPackage({first, second, child});
    BOOST_REQUIRE_MESSAGE(result.m_state.IsValid(), result.m_state.ToString());
    CheckPool({first, second, child});
    CheckGraph(first, {first}, {first, child});
    CheckGraph(second, {second}, {second, child});
    CheckGraph(child, {first, second, child}, {child});
}

// Resubmitting an existing parent in a package does not duplicate its entry or charge its fee a second time.
BOOST_AUTO_TEST_CASE(package_deduplicates_existing_mweb_parent)
{
    const auto parent_mweb = Pegin();
    const auto parent = FundPegin(parent_mweb);
    const auto child = MakeTransactionRef(WithMWEB(Spend(parent_mweb.GetOutputs().front())));
    Accept(parent, CANONICAL_FEE + MWEB_FEE);
    const auto result = SubmitPackage({parent, child});
    BOOST_REQUIRE_MESSAGE(result.m_state.IsValid(), result.m_state.ToString());
    BOOST_REQUIRE_EQUAL(result.m_tx_results.size(), 2U);
    BOOST_CHECK(result.m_tx_results.at(parent->GetWitnessHash()).m_result_type == MempoolAcceptResult::ResultType::MEMPOOL_ENTRY);
    BOOST_CHECK(result.m_tx_results.at(child->GetWitnessHash()).m_result_type == MempoolAcceptResult::ResultType::VALID);
    CheckPool({parent, child});
    CheckGraph(child, {parent, child}, {child});
    LOCK(m_pool.cs);
    BOOST_CHECK_EQUAL(m_pool.GetTotalFee(), CANONICAL_FEE + 2 * MWEB_FEE);
}

// MWEB output IDs determine package ordering just like canonical outpoints; a child-before-parent package is rejected.
BOOST_AUTO_TEST_CASE(package_requires_mweb_parent_before_child)
{
    const auto parent_mweb = Pegin();
    const auto parent = FundPegin(parent_mweb);
    const auto child = MakeTransactionRef(WithMWEB(Spend(parent_mweb.GetOutputs().front())));
    const auto result = SubmitPackage({child, parent});
    BOOST_CHECK(result.m_state.GetResult() == PackageValidationResult::PCKG_POLICY);
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "package-not-sorted");
    BOOST_CHECK(result.m_tx_results.empty());
    CheckPool({});
}

// Two transactions spending the same MWEB output conflict within a package, without affecting an unrelated pool entry.
BOOST_AUTO_TEST_CASE(package_rejects_conflicting_mweb_spends)
{
    const auto funding = FundMWEB();
    const auto first = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front())));
    const auto second = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front(), 2 * MWEB_FEE)));
    const auto independent = FundPegin(Pegin());
    Accept(independent, CANONICAL_FEE + MWEB_FEE);
    const auto result = SubmitPackage({first, second});
    BOOST_CHECK(result.m_state.GetResult() == PackageValidationResult::PCKG_POLICY);
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "conflict-in-package");
    CheckPool({independent});
}

// A failed dry run must discard temporary parent outputs even when the child fails after successfully finding them.
BOOST_AUTO_TEST_CASE(failed_package_discards_temporary_mweb_coins)
{
    const auto parent_mweb = Pegin();
    const auto parent = FundPegin(parent_mweb);
    const auto& output = parent_mweb.GetOutputs().front();
    const auto wrong_key = test::TxBuilder()
        .AddInput(output.GetAmount(), SecretKey::Random(), output.GetBlind(), output.GetOutputID())
        .AddOutput(output.GetAmount() - MWEB_FEE).AddPlainKernel(MWEB_FEE).Build();
    BOOST_REQUIRE(!wrong_key.GetTransaction()->Validate());
    const auto invalid_child = MakeTransactionRef(WithMWEB(wrong_key));
    const auto result = SubmitPackage({parent, invalid_child}, /*test_accept=*/true);
    BOOST_CHECK(result.m_state.GetResult() == PackageValidationResult::PCKG_TX);
    BOOST_REQUIRE_EQUAL(result.m_tx_results.count(invalid_child->GetWitnessHash()), 1U);
    BOOST_CHECK_EQUAL(result.m_tx_results.at(invalid_child->GetWitnessHash()).m_state.GetRejectReason(), "bad-txns-input-mismatch");
    CheckPool({});
    BOOST_CHECK(!m_view->HasCoin(output.GetOutputID()));
    const auto valid_child = MakeTransactionRef(WithMWEB(Spend(output)));
    Reject(valid_child, TxValidationResult::TX_MISSING_INPUTS, "bad-txns-inputs-missingorspent");
    const auto retry = SubmitPackage({parent, valid_child});
    BOOST_REQUIRE_MESSAGE(retry.m_state.IsValid(), retry.m_state.ToString());
    CheckPool({parent, valid_child});
}

BOOST_AUTO_TEST_SUITE_END()
