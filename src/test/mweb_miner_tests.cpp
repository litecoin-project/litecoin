// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/tx_verify.h>
#include <mweb/mweb_miner.h>
#include <mw/consensus/Params.h>
#include <mw/crypto/Blinds.h>
#include <mw/crypto/KeyDerivation.h>
#include <mw/crypto/PublicKeys.h>
#include <mw/models/tx/MutableTx.h>
#include <mw/node/BlockValidator.h>
#include <mw/node/CoinsView.h>
#include <node/miner.h>
#include <script/standard.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <validation.h>

#include <test_framework/TxBuilder.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace {

constexpr CAmount FUNDING_AMOUNT{10 * COIN};
constexpr CAmount MWEB_FEE{10'000};
constexpr CAmount CANONICAL_FEE{20'000};

CMutableTransaction WithMWEB(const mw::Transaction::CPtr& mweb_tx)
{
    CMutableTransaction tx;
    tx.mweb_tx = mw::MutableTx::From(*mweb_tx);
    for (const PegInCoin& pegin : mweb_tx->GetPegIns()) {
        tx.vout.emplace_back(pegin.GetAmount(), GetScriptForPegin(pegin.GetKernelID()));
    }
    if (!tx.vout.empty()) {
        tx.vin.emplace_back(uint256{mweb_tx->GetHash().vec()}, 0);
    }
    return tx;
}

CMutableTransaction WithMWEB(const test::Tx& tx)
{
    return WithMWEB(tx.GetTransaction());
}

// A signed, zero-value kernel adds an exact amount of weight without thousands
// of outputs or invalid signatures obscuring the limit under test.
mw::Transaction::CPtr WithWeight(const test::Tx& tx, const size_t weight)
{
    const auto& original = tx.GetTransaction();
    BOOST_REQUIRE_GE(weight, original->CalcWeight() + mw::BASE_KERNEL_WEIGHT);
    const size_t extra_bytes = (weight - original->CalcWeight() - mw::BASE_KERNEL_WEIGHT) * mw::BYTES_PER_WEIGHT;
    const BlindingFactor blind = BlindingFactor::Random();
    auto kernels = original->GetKernels();
    kernels.push_back(mw::Kernel::Create(blind, std::nullopt, 0, std::nullopt, {}, std::nullopt,
                                       std::vector<uint8_t>(extra_bytes, 0)));
    const auto weighted = mw::Transaction::Create(
        Blinds(original->GetKernelOffset()).Sub(blind).Total(), original->GetStealthOffset(),
        original->GetInputs(), original->GetOutputs(), std::move(kernels));
    BOOST_REQUIRE_EQUAL(weighted->CalcWeight(), weight);
    return weighted;
}

/**
 * A real chainstate and mempool, with a small synthetic previous MWEB block.
 * Only FundMWEB connects outputs; building candidates must leave that view alone.
 * The recipient keys let children spend the exact outputs their parents create.
 */
class MWEBMinerTestingSetup : public TestingSetup
{
public:
    MWEBMinerTestingSetup()
        : TestingSetup{CBaseChainParams::REGTEST, {"-vbparams=mweb:-1:9223372036854775807:0:0"}},
          m_view{m_node.chainman->ActiveChainstate().CoinsTip().GetMWEBCacheView()},
          m_address{PublicKey::From(SecretKey::Random()), PublicKey::From(m_spend_key)}
    {
        m_previous.nHeight = 0;
        m_previous.hogex_hash = uint256::ONE;
        const auto previous_block = mw::CoinsViewCache(m_view).BuildNextBlock(0, {});
        m_view->ApplyBlock(previous_block);
        m_previous.mweb_header = previous_block->GetHeader();
        StartBlock();
    }

    test::Tx Pegin(const CAmount amount = FUNDING_AMOUNT, const CAmount fee = MWEB_FEE) const
    {
        return test::TxBuilder()
            .AddPeginKernel(amount)
            .AddOutput(amount - fee, m_sender_key, m_address)
            .AddPlainKernel(fee)
            .Build();
    }

    test::Tx Spend(const test::TxOutput& output, const CAmount fee = MWEB_FEE,
                   const std::vector<PegOutCoin>& pegouts = {}) const
    {
        const SecretKey shared_secret = mw::DeriveSharedSecret(m_sender_key, m_address, output.GetAmount());
        const SecretKey output_key = mw::DeriveOutputSpendKey(m_spend_key, shared_secret);
        test::TxBuilder builder;
        builder.AddInput(output.GetAmount(), output_key, output.GetBlind(), output.GetOutputID());
        CAmount change = output.GetAmount() - fee;
        for (const PegOutCoin& pegout : pegouts) change -= pegout.GetAmount();
        BOOST_REQUIRE_GE(change, 0);
        if (change > 0) builder.AddOutput(change, m_sender_key, m_address);
        if (pegouts.empty()) {
            builder.AddPlainKernel(fee);
        } else {
            builder.AddPegoutKernel(pegouts, fee);
        }
        return builder.Build();
    }

    void FundMWEB(const test::Tx& funding)
    {
        LOCK(cs_main);
        const auto block = mw::CoinsViewCache(m_view).BuildNextBlock(m_previous.nHeight, {funding.GetTransaction()});
        m_view->ApplyBlock(block);
        m_previous.mweb_header = block->GetHeader();
        m_previous.mweb_amount = *block->GetSupplyChange();
        StartBlock();
    }

    void StartBlock()
    {
        LOCK(cs_main);
        m_miner.NewBlock(*m_node.chainman, m_previous.nHeight + 1);
    }

    void CheckRejectedWithoutChangingCandidate(const CMutableTransaction& invalid)
    {
        const auto before = MakeTransactionRef(WithMWEB(Pegin(2 * COIN)));
        const auto after = MakeTransactionRef(WithMWEB(Pegin(3 * COIN)));
        BOOST_REQUIRE(Add(before));
        BOOST_CHECK(!Add(MakeTransactionRef(invalid)));
        BOOST_REQUIRE(Add(after));
        CheckCandidate(Finish({before, after}), {before, after}, 5 * COIN - 2 * MWEB_FEE, 2 * MWEB_FEE);
    }

    CTxMemPool::txiter Queue(const CTransactionRef& tx, const CAmount canonical_fee = 0)
    {
        LOCK(m_node.mempool->cs);
        auto iter = m_node.mempool->mapTx.find(tx->GetHash());
        if (iter == m_node.mempool->mapTx.end()) {
            TestMemPoolEntryHelper entry;
            m_node.mempool->addUnchecked(entry
                .Fee(canonical_fee + tx->mweb_tx.GetFee().value_or(0))
                .SigOpsCost(WITNESS_SCALE_FACTOR * GetLegacySigOpCount(*tx))
                .FromTx(tx));
            iter = m_node.mempool->mapTx.find(tx->GetHash());
        }
        return iter;
    }

    bool Add(const CTransactionRef& tx)
    {
        LOCK2(cs_main, m_node.mempool->cs);
        return m_miner.AddMWEBTransaction(Queue(tx));
    }

    node::CBlockTemplate Finish(const std::vector<CTransactionRef>& accepted = {})
    {
        LOCK(cs_main);
        node::CBlockTemplate result;
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        coinbase.vout.emplace_back(50 * COIN, CScript() << OP_TRUE);
        result.block.vtx.push_back(MakeTransactionRef(coinbase));
        for (const auto& tx : accepted) {
            if (!tx->IsMWEBOnly()) {
                CMutableTransaction stripped{*tx};
                stripped.mweb_tx.SetNull();
                result.block.vtx.push_back(MakeTransactionRef(stripped));
            }
        }
        result.vTxFees.resize(result.block.vtx.size(), 0);
        result.vTxSigOpsCost.resize(result.block.vtx.size(), 0);
        CAmount fees{0};
        m_miner.AddHogExTransaction(&m_previous, &result.block, &result, fees);
        return result;
    }

    // Check the entire candidate, so rejected transactions cannot leak inputs,
    // outputs, kernels, fees, or sigops into an otherwise successful block.
    void CheckCandidate(const node::CBlockTemplate& candidate, const std::vector<CTransactionRef>& accepted,
                        const CAmount balance, const CAmount fees, const int64_t sigops = 0)
    {
        const CBlock& block = candidate.block;
        BOOST_REQUIRE(!block.mweb_block.IsNull());
        BOOST_REQUIRE(!block.vtx.empty());
        const CTransaction& hogex = *block.vtx.back();
        BOOST_CHECK(hogex.IsHogEx());
        BOOST_CHECK(!hogex.HasMWEBTx());
        BOOST_REQUIRE(!hogex.vout.empty());
        BOOST_CHECK_EQUAL(hogex.vout.front().nValue, balance);
        BOOST_CHECK(hogex.vout.front().scriptPubKey == (CScript() << OP_8 << block.mweb_block.GetHash().vec()));
        BOOST_CHECK_EQUAL(block.mweb_block.GetHeight(), m_previous.nHeight + 1);
        BOOST_REQUIRE_EQUAL(candidate.vTxFees.size(), block.vtx.size());
        BOOST_REQUIRE_EQUAL(candidate.vTxSigOpsCost.size(), block.vtx.size());
        BOOST_CHECK_EQUAL(candidate.vTxFees.back(), fees);
        BOOST_CHECK_EQUAL(candidate.vTxSigOpsCost.back(), sigops);
        BOOST_REQUIRE(block.mweb_block.GetTotalFee().has_value());
        BOOST_CHECK_EQUAL(*block.mweb_block.GetTotalFee(), fees);

        std::vector<CTxIn> expected_inputs;
        if (!m_previous.hogex_hash.IsNull()) expected_inputs.emplace_back(m_previous.hogex_hash, 0);
        std::vector<CTxOut> expected_outputs{hogex.vout.front()};
        std::vector<mw::Input> inputs;
        std::vector<mw::Output> outputs;
        std::vector<mw::Kernel> kernels;
        for (const auto& tx : accepted) {
            for (size_t i = 0; i < tx->vout.size(); ++i) {
                if (IsPegInOutput(tx->vout[i])) expected_inputs.emplace_back(tx->GetHash(), i);
            }
            for (const PegOutCoin& pegout : tx->mweb_tx.GetPegOuts()) {
                expected_outputs.emplace_back(pegout.GetAmount(), pegout.GetScriptPubKey());
            }
            const auto& body = tx->mweb_tx.m_transaction->GetBody();
            inputs.insert(inputs.end(), body.GetInputs().begin(), body.GetInputs().end());
            outputs.insert(outputs.end(), body.GetOutputs().begin(), body.GetOutputs().end());
            kernels.insert(kernels.end(), body.GetKernels().begin(), body.GetKernels().end());
        }
        std::sort(inputs.begin(), inputs.end(), InputSort());
        std::sort(outputs.begin(), outputs.end(), mw::OutputSort());
        std::sort(kernels.begin(), kernels.end(), KernelSort());
        BOOST_CHECK(hogex.vin == expected_inputs);
        BOOST_CHECK(hogex.vout == expected_outputs);
        BOOST_CHECK(block.mweb_block.m_block->GetInputs() == inputs);
        BOOST_CHECK(block.mweb_block.m_block->GetOutputs() == outputs);
        BOOST_CHECK(block.mweb_block.m_block->GetKernels() == kernels);
        std::vector<PegInCoin> pegins;
        for (const auto& tx : block.vtx) {
            for (const CTxOut& output : tx->vout) {
                mw::Hash kernel_id;
                if (output.scriptPubKey.IsMWEBPegin(&kernel_id)) pegins.emplace_back(output.nValue, kernel_id);
            }
        }
        std::vector<PegOutCoin> pegouts;
        for (size_t i = 1; i < hogex.vout.size(); ++i) {
            pegouts.emplace_back(hogex.vout[i].nValue, hogex.vout[i].scriptPubKey);
        }
        BOOST_CHECK(BlockValidator::ValidateBlock(block.mweb_block.m_block, pegins, pegouts));
        mw::CoinsViewCache connected{m_view};
        BOOST_CHECK_NO_THROW(connected.ApplyBlock(block.mweb_block.m_block));
    }

    // Supply a spendable canonical input and matching previous HogAddr for the
    // full assembler's TestBlockValidity pass, without mining hundreds of blocks.
    void PrepareAssembler()
    {
        LOCK(cs_main);
        CBlockIndex* tip = m_node.chainman->ActiveChain().Tip();
        tip->hogex_hash = m_previous.hogex_hash;
        tip->mweb_header = m_previous.mweb_header;
        tip->mweb_amount = m_previous.mweb_amount;
        m_node.chainman->ActiveChainstate().CoinsTip().AddCoin(
            COutPoint{tip->hogex_hash, 0},
            Coin{CTxOut{tip->mweb_amount, CScript() << OP_8 << tip->mweb_header->GetHash().vec()}, tip->nHeight, false}, false);
    }

    void QueueFunded(const CTransactionRef& tx, const CAmount canonical_fee = CANONICAL_FEE)
    {
        LOCK(cs_main);
        BOOST_REQUIRE_EQUAL(tx->vin.size(), 1U);
        m_node.chainman->ActiveChainstate().CoinsTip().AddCoin(tx->vin.front().prevout,
            Coin{CTxOut{tx->GetValueOut() + canonical_fee, CScript() << OP_TRUE}, 0, false}, false);
        Queue(tx, canonical_fee);
    }

    std::unique_ptr<node::CBlockTemplate> Assemble()
    {
        node::BlockAssembler::Options options;
        options.blockMinFeeRate = CFeeRate{0};
        return node::BlockAssembler{m_node.chainman->ActiveChainstate(), m_node.mempool.get(), options}
            .CreateNewBlock(CScript() << OP_TRUE);
    }

    MWEB::Miner m_miner;
    CBlockIndex m_previous;
    mw::CoinsViewCache::Ptr m_view;
    SecretKey m_spend_key{SecretKey::Random()};
    SecretKey m_sender_key{SecretKey::Random()};
    StealthAddress m_address;
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(mweb_miner_tests, MWEBMinerTestingSetup)

// Before NewBlock initializes the builder, MWEB transactions cannot be staged.
BOOST_AUTO_TEST_CASE(uninitialized_miner_rejects_transactions)
{
    MWEB::Miner inactive;
    const auto pegin = MakeTransactionRef(WithMWEB(Pegin()));
    LOCK2(cs_main, m_node.mempool->cs);
    BOOST_CHECK(!inactive.AddMWEBTransaction(Queue(pegin)));
}

// The first empty extension block creates a zero-valued HogAddr without a previous HogEx input.
BOOST_AUTO_TEST_CASE(first_empty_block_creates_hogaddr)
{
    m_previous.hogex_hash.SetNull();
    const auto block = Finish();
    CheckCandidate(block, {}, 0, 0);
    BOOST_CHECK(block.block.vtx.back()->vin.empty());
}

// The first funded extension block spends only its peg-in, then deducts the MWEB fee.
BOOST_AUTO_TEST_CASE(first_pegin_funds_hogaddr)
{
    m_previous.hogex_hash.SetNull();
    const auto pegin = MakeTransactionRef(WithMWEB(Pegin()));
    BOOST_REQUIRE(Add(pegin));
    CheckCandidate(Finish({pegin}), {pegin}, FUNDING_AMOUNT - MWEB_FEE, MWEB_FEE);
}

// An empty successor rolls the previous HogAddr forward without changing its balance or UTXO roots.
BOOST_AUTO_TEST_CASE(empty_successor_preserves_previous_state)
{
    FundMWEB(Pegin(FUNDING_AMOUNT, 0));
    const auto block = Finish();
    CheckCandidate(block, {}, FUNDING_AMOUNT, 0);
    const auto& header = block.block.mweb_block.GetMWEBHeader();
    BOOST_CHECK(header->GetOutputRoot() == m_previous.mweb_header->GetOutputRoot());
    BOOST_CHECK(header->GetLeafsetRoot() == m_previous.mweb_header->GetLeafsetRoot());
    BOOST_CHECK(header->GetKernelOffset() == m_previous.mweb_header->GetKernelOffset());
}

// Multiple peg-ins add to the existing balance and charge each MWEB fee exactly once.
BOOST_AUTO_TEST_CASE(pegins_accumulate_balance_and_fees)
{
    FundMWEB(Pegin(FUNDING_AMOUNT, 0));
    const auto first = MakeTransactionRef(WithMWEB(Pegin(2 * COIN)));
    const auto second = MakeTransactionRef(WithMWEB(Pegin(3 * COIN, 2 * MWEB_FEE)));
    BOOST_REQUIRE(Add(first));
    BOOST_REQUIRE(Add(second));
    CheckCandidate(Finish({first, second}), {first, second}, 15 * COIN - 3 * MWEB_FEE, 3 * MWEB_FEE);
}

// HogEx follows canonical output order and indexes, even with change outputs between reversed peg-ins.
BOOST_AUTO_TEST_CASE(pegin_inputs_use_canonical_output_order)
{
    const auto mweb_tx = test::TxBuilder().AddPeginKernel(2 * COIN).AddPeginKernel(3 * COIN)
        .AddOutput(5 * COIN).Build();
    CMutableTransaction tx = WithMWEB(mweb_tx);
    std::reverse(tx.vout.begin(), tx.vout.end());
    tx.vout.insert(tx.vout.begin(), CTxOut{COIN, CScript() << OP_TRUE});
    tx.vout.insert(tx.vout.begin() + 2, CTxOut{COIN, CScript() << OP_TRUE});
    const auto pegin = MakeTransactionRef(tx);
    BOOST_REQUIRE(Add(pegin));
    const auto block = Finish({pegin});
    CheckCandidate(block, {pegin}, 5 * COIN, 0);
    const auto& inputs = block.block.vtx.back()->vin;
    BOOST_REQUIRE_EQUAL(inputs.size(), 3U);
    BOOST_CHECK(inputs[1].prevout == COutPoint(pegin->GetHash(), 1));
    BOOST_CHECK(inputs[2].prevout == COutPoint(pegin->GetHash(), 3));
}

// A confidential transfer spends a confirmed output and reduces the HogAddr only by its fee.
BOOST_AUTO_TEST_CASE(transfer_spends_confirmed_output)
{
    const auto funding = Pegin(FUNDING_AMOUNT, 0);
    FundMWEB(funding);
    const auto transfer = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front())));
    BOOST_REQUIRE(transfer->IsMWEBOnly());
    BOOST_REQUIRE(Add(transfer));
    CheckCandidate(Finish({transfer}), {transfer}, FUNDING_AMOUNT - MWEB_FEE, MWEB_FEE);
}

// Multiple peg-outs become HogEx outputs, with their scripts, amounts, fees, and sigops preserved.
BOOST_AUTO_TEST_CASE(pegouts_pay_recipients_and_return_change)
{
    const auto funding = Pegin(FUNDING_AMOUNT, 0);
    FundMWEB(funding);
    const std::vector<PegOutCoin> recipients{
        {2 * COIN, CScript() << OP_CHECKSIG},
        {3 * COIN, CScript() << OP_CHECKSIGVERIFY << OP_TRUE}};
    const auto pegout = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front(), MWEB_FEE, recipients)));
    BOOST_REQUIRE(Add(pegout));
    CheckCandidate(Finish({pegout}), {pegout}, 5 * COIN - MWEB_FEE, MWEB_FEE, 8);
}

// Withdrawing the full remaining balance leaves a zero-valued HogAddr and no new MWEB outputs.
BOOST_AUTO_TEST_CASE(full_pegout_leaves_empty_hogaddr)
{
    const auto funding = Pegin(FUNDING_AMOUNT, 0);
    FundMWEB(funding);
    const auto pegout = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front(), MWEB_FEE,
        {{FUNDING_AMOUNT - MWEB_FEE, CScript() << OP_TRUE}})));
    BOOST_REQUIRE(Add(pegout));
    const auto block = Finish({pegout});
    CheckCandidate(block, {pegout}, 0, MWEB_FEE);
    BOOST_CHECK(block.block.mweb_block.m_block->GetOutputs().empty());
}

// Two identical peg-out recipients remain two payments, not a deduplicated HogEx output.
BOOST_AUTO_TEST_CASE(duplicate_pegout_recipients_are_preserved)
{
    const auto funding = Pegin(FUNDING_AMOUNT, 0);
    FundMWEB(funding);
    const PegOutCoin recipient{2 * COIN, CScript() << OP_CHECKSIG};
    const auto pegout = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front(), MWEB_FEE,
                                                         {recipient, recipient})));
    BOOST_REQUIRE(Add(pegout));
    const auto block = Finish({pegout});
    CheckCandidate(block, {pegout}, 6 * COIN - MWEB_FEE, MWEB_FEE, 8);
    BOOST_REQUIRE_EQUAL(block.block.vtx.back()->vout.size(), 3U);
    BOOST_CHECK(block.block.vtx.back()->vout[1] == block.block.vtx.back()->vout[2]);
}

// A hybrid can peg in and peg out in the same transaction; HogEx receives only the net amount after fees.
BOOST_AUTO_TEST_CASE(hybrid_pegin_and_pegout_share_one_hogex)
{
    const auto hybrid = MakeTransactionRef(WithMWEB(test::TxBuilder()
        .AddPeginKernel(FUNDING_AMOUNT)
        .AddOutput(7 * COIN - MWEB_FEE)
        .AddPegoutKernel({{3 * COIN, CScript() << OP_CHECKSIG}}, MWEB_FEE)
        .Build()));
    BOOST_REQUIRE(Add(hybrid));
    CheckCandidate(Finish({hybrid}), {hybrid}, 7 * COIN - MWEB_FEE, MWEB_FEE, 4);
}

// A child rejected before its parent becomes eligible after that parent's output is staged in the same block.
BOOST_AUTO_TEST_CASE(child_can_be_retried_after_parent_is_staged)
{
    const auto parent_mweb = Pegin();
    const auto parent = MakeTransactionRef(WithMWEB(parent_mweb));
    const auto child_mweb = Spend(parent_mweb.GetOutputs().front());
    const auto child = MakeTransactionRef(WithMWEB(child_mweb));
    BOOST_REQUIRE(!child_mweb.GetTransaction()->Validate());
    BOOST_CHECK(!Add(child));
    BOOST_REQUIRE(Add(parent));
    BOOST_REQUIRE(Add(child));
    const auto block = Finish({parent, child});
    CheckCandidate(block, {parent, child}, FUNDING_AMOUNT - 2 * MWEB_FEE, 2 * MWEB_FEE);
    mw::CoinsViewCache connected{m_view};
    connected.ApplyBlock(block.block.mweb_block.m_block);
    BOOST_CHECK(!connected.HasCoin(parent_mweb.GetOutputs().front().GetOutputID()));
    BOOST_CHECK(connected.HasCoin(child_mweb.GetOutputs().front().GetOutputID()));
}

// A same-block full withdrawal would cancel every staged commitment; rejecting it must preserve the parent peg-in.
BOOST_AUTO_TEST_CASE(zero_commitment_sum_preserves_parent)
{
    const auto parent_mweb = Pegin();
    const auto parent = MakeTransactionRef(WithMWEB(parent_mweb));
    const auto withdrawal = Spend(parent_mweb.GetOutputs().front(), MWEB_FEE,
        {{FUNDING_AMOUNT - 2 * MWEB_FEE, CScript() << OP_CHECKSIG}});
    BOOST_REQUIRE(!withdrawal.GetTransaction()->Validate());
    BOOST_REQUIRE(Add(parent));
    BOOST_CHECK(!Add(MakeTransactionRef(WithMWEB(withdrawal))));
    CheckCandidate(Finish({parent}), {parent}, FUNDING_AMOUNT - MWEB_FEE, MWEB_FEE);
}

// A conflicting withdrawal cannot replace a staged spend or leak its peg-outs, fees, or sigops into HogEx.
BOOST_AUTO_TEST_CASE(double_spend_preserves_first_transaction)
{
    const auto funding = Pegin(FUNDING_AMOUNT, 0);
    FundMWEB(funding);
    const auto transfer = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front())));
    const auto conflict_mweb = Spend(funding.GetOutputs().front(), 2 * MWEB_FEE,
                                    {{3 * COIN, CScript() << OP_CHECKSIG}});
    BOOST_REQUIRE(!conflict_mweb.GetTransaction()->Validate());
    BOOST_REQUIRE(Add(transfer));
    BOOST_CHECK(!Add(MakeTransactionRef(WithMWEB(conflict_mweb))));
    const auto pegin = MakeTransactionRef(WithMWEB(Pegin(2 * COIN)));
    BOOST_REQUIRE(Add(pegin));
    CheckCandidate(Finish({transfer, pegin}), {transfer, pegin}, 12 * COIN - 2 * MWEB_FEE, 2 * MWEB_FEE);
}

// Staging the same peg-in twice must not duplicate its outputs, kernels, HogEx input, or fee.
BOOST_AUTO_TEST_CASE(duplicate_staged_output_is_rejected)
{
    const auto pegin = MakeTransactionRef(WithMWEB(Pegin()));
    BOOST_REQUIRE(Add(pegin));
    BOOST_CHECK(!Add(pegin));
    CheckCandidate(Finish({pegin}), {pegin}, FUNDING_AMOUNT - MWEB_FEE, MWEB_FEE);
}

// Replaying a confirmed peg-in is rejected because its output already exists on chain.
BOOST_AUTO_TEST_CASE(duplicate_confirmed_output_is_rejected)
{
    const auto funding = Pegin(FUNDING_AMOUNT, 0);
    FundMWEB(funding);
    BOOST_CHECK(!Add(MakeTransactionRef(WithMWEB(funding))));
    const auto transfer = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front())));
    BOOST_REQUIRE(Add(transfer));
    CheckCandidate(Finish({transfer}), {transfer}, FUNDING_AMOUNT - MWEB_FEE, MWEB_FEE);
}

// A correctly signed spend of an output absent from both chainstate and the candidate is rejected without side effects.
BOOST_AUTO_TEST_CASE(missing_input_is_rejected)
{
    const auto unconfirmed = Pegin(FUNDING_AMOUNT, 0);
    const auto spend = Spend(unconfirmed.GetOutputs().front(), MWEB_FEE,
                             {{3 * COIN, CScript() << OP_CHECKSIG}});
    BOOST_REQUIRE(!spend.GetTransaction()->Validate());
    CheckRejectedWithoutChangingCandidate(WithMWEB(spend));
}

// Invalid MWEB signatures reject a candidate even when its canonical peg-in amounts and kernel IDs match.
BOOST_AUTO_TEST_CASE(invalid_output_signature_is_rejected)
{
    CMutableTransaction invalid = WithMWEB(Pegin());
    invalid.mweb_tx.outputs.front().signature = Signature{};
    CheckRejectedWithoutChangingCandidate(invalid);
}

// Every MWEB peg-in kernel needs a matching canonical output; a missing one leaves the candidate untouched.
BOOST_AUTO_TEST_CASE(missing_canonical_pegin_is_rejected)
{
    CMutableTransaction invalid = WithMWEB(test::TxBuilder()
        .AddPeginKernel(2 * COIN).AddPeginKernel(3 * COIN).AddOutput(5 * COIN).Build());
    invalid.vout.pop_back();
    CheckRejectedWithoutChangingCandidate(invalid);
}

// An extra canonical peg-in with no corresponding MWEB kernel cannot be swept into HogEx.
BOOST_AUTO_TEST_CASE(extra_canonical_pegin_is_rejected)
{
    CMutableTransaction invalid = WithMWEB(Pegin());
    invalid.vout.emplace_back(COIN, GetScriptForPegin(mw::Hash{}));
    CheckRejectedWithoutChangingCandidate(invalid);
}

// Matching the peg-in kernel ID is insufficient when the canonical amount differs by even one satoshi.
BOOST_AUTO_TEST_CASE(pegin_amount_mismatch_is_rejected)
{
    CMutableTransaction invalid = WithMWEB(Pegin());
    --invalid.vout.front().nValue;
    CheckRejectedWithoutChangingCandidate(invalid);
}

// Matching the peg-in amount is insufficient when the canonical output names a different kernel.
BOOST_AUTO_TEST_CASE(pegin_kernel_mismatch_is_rejected)
{
    CMutableTransaction invalid = WithMWEB(Pegin());
    invalid.vout.front().scriptPubKey = GetScriptForPegin(mw::Hash{});
    CheckRejectedWithoutChangingCandidate(invalid);
}

// A single MWEB kernel cannot justify two identical canonical peg-in outputs.
BOOST_AUTO_TEST_CASE(duplicate_canonical_pegin_is_rejected)
{
    CMutableTransaction invalid = WithMWEB(Pegin());
    invalid.vout.push_back(invalid.vout.front());
    CheckRejectedWithoutChangingCandidate(invalid);
}

// Individually in-range peg-ins are rejected if their sum exceeds MAX_MONEY.
BOOST_AUTO_TEST_CASE(aggregate_pegin_amount_out_of_range_is_rejected)
{
    auto invalid = mw::MutableTx::From(*test::TxBuilder()
        .AddPeginKernel(2 * COIN).AddPeginKernel(3 * COIN).AddOutput(5 * COIN).Build().GetTransaction());
    for (auto& kernel : invalid.kernels) kernel.pegin = MAX_MONEY;
    CheckRejectedWithoutChangingCandidate(WithMWEB(*invalid.Finalized()));
}

// Individually in-range peg-outs are rejected if their sum exceeds MAX_MONEY.
BOOST_AUTO_TEST_CASE(aggregate_pegout_amount_out_of_range_is_rejected)
{
    auto invalid = mw::MutableTx::From(*Pegin().GetTransaction());
    invalid.kernels.front().SetPegOuts({
        {MAX_MONEY, CScript() << OP_CHECKSIG}, {1, CScript() << OP_TRUE}});
    CheckRejectedWithoutChangingCandidate(WithMWEB(*invalid.Finalized()));
}

// An out-of-range MWEB fee is rejected before it can affect the HogAddr balance or template fees.
BOOST_AUTO_TEST_CASE(fee_out_of_range_is_rejected)
{
    auto invalid = mw::MutableTx::From(*Pegin().GetTransaction());
    invalid.kernels.front().fee = MAX_MONEY + 1;
    CheckRejectedWithoutChangingCandidate(WithMWEB(*invalid.Finalized()));
}

// Valid individual kernel fees still cannot sum to more than MAX_MONEY.
BOOST_AUTO_TEST_CASE(aggregate_fee_out_of_range_is_rejected)
{
    auto invalid = mw::MutableTx::From(*Pegin().GetTransaction());
    for (auto& kernel : invalid.kernels) kernel.fee = MAX_MONEY;
    CheckRejectedWithoutChangingCandidate(WithMWEB(*invalid.Finalized()));
}

// The consensus weight limit is inclusive; a full candidate rejects another transaction without losing existing work.
BOOST_AUTO_TEST_CASE(consensus_weight_limit_is_inclusive)
{
    const auto weighted = WithWeight(Pegin(), mw::MAX_BLOCK_WEIGHT);
    BOOST_REQUIRE(!weighted->Validate());
    const auto full = MakeTransactionRef(WithMWEB(weighted));
    BOOST_REQUIRE(Add(full));
    BOOST_CHECK(!Add(MakeTransactionRef(WithMWEB(Pegin()))));
    CheckCandidate(Finish({full}), {full}, FUNDING_AMOUNT - MWEB_FEE, MWEB_FEE);
}

// Starting another candidate clears previously staged peg-ins, peg-outs, fees, sigops, and builder contents.
BOOST_AUTO_TEST_CASE(new_block_discards_previous_candidate)
{
    const auto abandoned = MakeTransactionRef(WithMWEB(test::TxBuilder()
        .AddPeginKernel(FUNDING_AMOUNT).AddOutput(7 * COIN - MWEB_FEE)
        .AddPegoutKernel({{3 * COIN, CScript() << OP_CHECKSIG}}, MWEB_FEE).Build()));
    BOOST_REQUIRE(Add(abandoned));
    CheckCandidate(Finish({abandoned}), {abandoned}, 7 * COIN - MWEB_FEE, MWEB_FEE, 4);

    ++m_previous.nHeight;
    StartBlock();
    CheckCandidate(Finish(), {}, 0, 0);
    const auto replacement = MakeTransactionRef(WithMWEB(Pegin(2 * COIN)));
    BOOST_REQUIRE(Add(replacement));
    CheckCandidate(Finish({replacement}), {replacement}, 2 * COIN - MWEB_FEE, MWEB_FEE);
}

// Building and rebuilding a candidate must not spend live UTXOs or change the active MWEB header, PMMR, or leafset.
BOOST_AUTO_TEST_CASE(building_candidates_does_not_mutate_chainstate)
{
    const auto funding = Pegin(FUNDING_AMOUNT, 0);
    FundMWEB(funding);
    const auto previous_header = m_view->GetBestHeader();
    const auto output_root = m_view->GetOutputPMMR()->Root();
    const auto leafset_root = m_view->GetLeafSet()->Root();
    const auto num_outputs = m_view->GetOutputPMMR()->GetNumLeaves();
    const auto transfer_mweb = Spend(funding.GetOutputs().front());
    const auto transfer = MakeTransactionRef(WithMWEB(transfer_mweb));
    BOOST_REQUIRE(Add(transfer));
    const auto first = Finish({transfer});
    const auto rebuilt = Finish({transfer});
    CheckCandidate(first, {transfer}, FUNDING_AMOUNT - MWEB_FEE, MWEB_FEE);
    CheckCandidate(rebuilt, {transfer}, FUNDING_AMOUNT - MWEB_FEE, MWEB_FEE);
    BOOST_CHECK(first.block.mweb_block.GetHash() == rebuilt.block.mweb_block.GetHash());
    BOOST_CHECK(first.block.vtx.back()->GetHash() == rebuilt.block.vtx.back()->GetHash());
    BOOST_CHECK(m_view->GetBestHeader() == previous_header);
    BOOST_CHECK(m_view->GetOutputPMMR()->Root() == output_root);
    BOOST_CHECK(m_view->GetLeafSet()->Root() == leafset_root);
    BOOST_CHECK_EQUAL(m_view->GetOutputPMMR()->GetNumLeaves(), num_outputs);
    BOOST_CHECK(m_view->HasCoin(funding.GetOutputs().front().GetOutputID()));
    BOOST_CHECK(!m_view->HasCoin(transfer_mweb.GetOutputs().front().GetOutputID()));
}

// A canonical-only transaction contributes no HogEx sigops, regardless of its own scripts.
BOOST_AUTO_TEST_CASE(hogex_sigops_are_zero_without_mweb)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin.front().scriptSig = CScript() << OP_CHECKMULTISIG;
    tx.vout.emplace_back(COIN, CScript() << OP_CHECKSIG);
    BOOST_CHECK_EQUAL(MWEB::Miner::GetHogExSigOpCost(CTransaction{tx}), 0);
}

// HogEx counts only peg-out opcodes, not pushed bytes or canonical scripts; CHECKMULTISIG costs 20 sigops.
BOOST_AUTO_TEST_CASE(hogex_sigops_count_only_pegout_opcodes)
{
    const CScript pushed_opcodes = CScript() << std::vector<uint8_t>{OP_CHECKSIG, OP_CHECKMULTISIG} << OP_DROP << OP_TRUE;
    CMutableTransaction tx = WithMWEB(test::TxBuilder()
        .AddPeginKernel(FUNDING_AMOUNT).AddOutput(7 * COIN)
        .AddPegoutKernel({
            {COIN, pushed_opcodes},
            {COIN, CScript() << OP_CHECKSIG << OP_CHECKSIGVERIFY},
            {COIN, CScript() << OP_2 << OP_CHECKMULTISIG}}, 0)
        .Build());
    tx.vin.front().scriptSig = CScript() << OP_CHECKSIG;
    tx.vout.emplace_back(COIN, CScript() << OP_CHECKMULTISIG);
    BOOST_CHECK_EQUAL(MWEB::Miner::GetHogExSigOpCost(CTransaction{tx}), (2 + 20) * WITNESS_SCALE_FACTOR);
}

// The full assembler strips hybrid MWEB data and splits canonical and HogEx fees without double-paying coinbase.
BOOST_AUTO_TEST_CASE(assembler_splits_hybrid_transaction_and_fees)
{
    PrepareAssembler();
    const auto pegin = MakeTransactionRef(WithMWEB(Pegin()));
    QueueFunded(pegin);
    const auto block = Assemble();
    CheckCandidate(*block, {pegin}, FUNDING_AMOUNT - MWEB_FEE, MWEB_FEE);
    BOOST_REQUIRE_EQUAL(block->block.vtx.size(), 3U);
    BOOST_CHECK(block->block.vtx[1]->GetHash() == pegin->GetHash());
    BOOST_CHECK(!block->block.vtx[1]->HasMWEBTx());
    BOOST_CHECK_EQUAL(block->vTxFees[1], CANONICAL_FEE);
    BOOST_CHECK_EQUAL(block->vTxFees[0], -(CANONICAL_FEE + MWEB_FEE));
    BOOST_CHECK_EQUAL(block->block.vtx[0]->GetValueOut(),
                      GetBlockSubsidy(1, m_node.chainman->GetConsensus()) + CANONICAL_FEE + MWEB_FEE);
    BOOST_CHECK(pegin->HasMWEBTx());
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 1U);
}

// Pure MWEB transfers appear only in the extension block; their fees are recorded on HogEx and coinbase.
BOOST_AUTO_TEST_CASE(assembler_keeps_pure_mweb_out_of_canonical_transactions)
{
    const auto funding = Pegin(FUNDING_AMOUNT, 0);
    FundMWEB(funding);
    PrepareAssembler();
    const auto transfer = MakeTransactionRef(WithMWEB(Spend(funding.GetOutputs().front())));
    Queue(transfer);
    const auto block = Assemble();
    CheckCandidate(*block, {transfer}, FUNDING_AMOUNT - MWEB_FEE, MWEB_FEE);
    BOOST_REQUIRE_EQUAL(block->block.vtx.size(), 2U);
    BOOST_CHECK_EQUAL(block->vTxFees[0], -MWEB_FEE);
    BOOST_CHECK_EQUAL(block->block.vtx[0]->GetValueOut(),
                      GetBlockSubsidy(1, m_node.chainman->GetConsensus()) + MWEB_FEE);
}

// A hybrid's peg-out sigops move to HogEx while sigops from ordinary canonical outputs stay on the stripped transaction.
BOOST_AUTO_TEST_CASE(assembler_splits_canonical_and_hogex_sigops)
{
    PrepareAssembler();
    CMutableTransaction tx = WithMWEB(test::TxBuilder()
        .AddPeginKernel(FUNDING_AMOUNT).AddOutput(7 * COIN - MWEB_FEE)
        .AddPegoutKernel({{3 * COIN, CScript() << OP_CHECKSIG}}, MWEB_FEE).Build());
    tx.vout.emplace_back(COIN, CScript() << OP_CHECKSIG);
    const auto hybrid = MakeTransactionRef(tx);
    QueueFunded(hybrid);
    const auto block = Assemble();
    CheckCandidate(*block, {hybrid}, 7 * COIN - MWEB_FEE, MWEB_FEE, 4);
    BOOST_REQUIRE_EQUAL(block->block.vtx.size(), 3U);
    BOOST_CHECK_EQUAL(block->vTxSigOpsCost[1], 4);
    BOOST_CHECK_EQUAL(block->vTxFees[1], CANONICAL_FEE);
    BOOST_CHECK_EQUAL(block->vTxFees[0], -(CANONICAL_FEE + MWEB_FEE));
}

// A fee-paying MWEB child brings its zero-fee peg-in parent into the block, with the parent staged first.
BOOST_AUTO_TEST_CASE(assembler_includes_parent_child_package)
{
    PrepareAssembler();
    const auto parent_mweb = Pegin(FUNDING_AMOUNT, 0);
    const auto parent = MakeTransactionRef(WithMWEB(parent_mweb));
    const auto child = MakeTransactionRef(WithMWEB(Spend(parent_mweb.GetOutputs().front(), 10 * MWEB_FEE)));
    QueueFunded(parent, 0);
    Queue(child);
    const auto block = Assemble();
    CheckCandidate(*block, {parent, child}, FUNDING_AMOUNT - 10 * MWEB_FEE, 10 * MWEB_FEE);
    BOOST_REQUIRE_EQUAL(block->block.vtx.size(), 3U);
    BOOST_CHECK(block->block.vtx[1]->GetHash() == parent->GetHash());
    BOOST_CHECK_EQUAL(block->vTxFees[1], 0);
    BOOST_CHECK_EQUAL(block->vTxFees[0], -10 * MWEB_FEE);
}

// An invalid peg-in and its MWEB descendant are skipped while an unrelated valid transaction still gets mined.
BOOST_AUTO_TEST_CASE(assembler_skips_rejected_parent_and_child)
{
    PrepareAssembler();
    const auto parent_mweb = Pegin();
    CMutableTransaction invalid = WithMWEB(parent_mweb);
    --invalid.vout.front().nValue;
    const auto parent = MakeTransactionRef(invalid);
    const auto child = MakeTransactionRef(WithMWEB(Spend(parent_mweb.GetOutputs().front())));
    const auto independent = MakeTransactionRef(WithMWEB(Pegin(2 * COIN)));
    QueueFunded(parent, COIN);
    Queue(child);
    QueueFunded(independent);
    const auto block = Assemble();
    CheckCandidate(*block, {independent}, 2 * COIN - MWEB_FEE, MWEB_FEE);
    BOOST_REQUIRE_EQUAL(block->block.vtx.size(), 3U);
    BOOST_CHECK(block->block.vtx[1]->GetHash() == independent->GetHash());
    BOOST_CHECK_EQUAL(block->vTxFees[0], -(CANONICAL_FEE + MWEB_FEE));
}

// A valid transaction one unit below the mining weight cap is included when its fee also covers that weight.
BOOST_AUTO_TEST_CASE(assembler_accepts_weight_below_mining_limit)
{
    PrepareAssembler();
    const auto weighted = WithWeight(Pegin(), mw::MAX_MINE_WEIGHT - 1);
    BOOST_REQUIRE(!weighted->Validate());
    const auto pegin = MakeTransactionRef(WithMWEB(weighted));
    QueueFunded(pegin, COIN);
    const auto block = Assemble();
    CheckCandidate(*block, {pegin}, FUNDING_AMOUNT - MWEB_FEE, MWEB_FEE);
    BOOST_REQUIRE_EQUAL(block->block.vtx.size(), 3U);
    BOOST_CHECK_EQUAL(block->vTxFees[0], -(COIN + MWEB_FEE));
}

// The mining cap is exclusive and lower than the consensus limit, so a valid transaction at the cap is skipped.
BOOST_AUTO_TEST_CASE(assembler_rejects_weight_at_mining_limit)
{
    PrepareAssembler();
    const auto weighted = WithWeight(Pegin(), mw::MAX_MINE_WEIGHT);
    BOOST_REQUIRE(!weighted->Validate());
    const auto pegin = MakeTransactionRef(WithMWEB(weighted));
    QueueFunded(pegin, COIN);
    const auto block = Assemble();
    CheckCandidate(*block, {}, 0, 0);
    BOOST_REQUIRE_EQUAL(block->block.vtx.size(), 2U);
    BOOST_CHECK_EQUAL(block->vTxFees[0], 0);
}

// Individually small enough transactions still share the mining weight budget; the last one cannot overfill it.
BOOST_AUTO_TEST_CASE(assembler_enforces_cumulative_mweb_weight)
{
    PrepareAssembler();
    const auto second_mweb = Pegin(2 * COIN);
    const size_t second_weight = second_mweb.GetTransaction()->CalcWeight();
    const auto first = MakeTransactionRef(WithMWEB(WithWeight(Pegin(), mw::MAX_MINE_WEIGHT - second_weight - 1)));
    const auto second = MakeTransactionRef(WithMWEB(second_mweb));
    const auto third = MakeTransactionRef(WithMWEB(Pegin(3 * COIN)));
    QueueFunded(first, COIN);
    QueueFunded(second, 2 * CANONICAL_FEE);
    QueueFunded(third, CANONICAL_FEE);
    const auto block = Assemble();
    CheckCandidate(*block, {first, second}, 12 * COIN - 2 * MWEB_FEE, 2 * MWEB_FEE);
    BOOST_REQUIRE_EQUAL(block->block.vtx.size(), 4U);
    BOOST_CHECK_EQUAL(block->vTxFees[0], -(COIN + 2 * CANONICAL_FEE + 2 * MWEB_FEE));
}

BOOST_AUTO_TEST_SUITE_END()
