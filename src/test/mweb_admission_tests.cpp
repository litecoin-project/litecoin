// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <consensus/amount.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <mw/consensus/Aggregation.h>
#include <mw/crypto/Blinds.h>
#include <mw/crypto/KeyDerivation.h>
#include <mw/crypto/Schnorr.h>
#include <mw/crypto/SecretKeys.h>
#include <mw/models/tx/MutableTx.h>
#include <mw/node/CoinsView.h>
#include <mweb/mweb_node.h>
#include <mweb/mweb_policy.h>
#include <policy/policy.h>
#include <script/standard.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <util/time.h>
#include <validation.h>

#include <test_framework/TxBuilder.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace {

constexpr CAmount FUNDING_AMOUNT{10 * COIN};
constexpr CAmount MWEB_FEE{10'000};
constexpr CAmount CANONICAL_FEE{20'000};
constexpr size_t RELAY_WEIGHT_LIMIT{mw::MAX_BLOCK_WEIGHT / 50};
constexpr size_t RELAY_INPUT_LIMIT{mw::MAX_NUM_INPUTS / 50};

CMutableTransaction WithMWEB(const mw::Transaction::CPtr& mweb_tx)
{
    CMutableTransaction tx;
    tx.mweb_tx = mw::MutableTx::From(*mweb_tx);
    for (const auto& pegin : mweb_tx->GetPegIns()) {
        tx.vout.emplace_back(pegin.GetAmount(), GetScriptForPegin(pegin.GetKernelID()));
    }
    return tx;
}

// Preserve valid signatures and balanced offsets when adding a feature-bearing kernel.
CMutableTransaction WithExtraKernel(CMutableTransaction tx, const std::optional<int32_t> lock_height = std::nullopt,
                                    const std::vector<uint8_t>& extra_data = {})
{
    const auto blind = BlindingFactor::Random();
    const auto kernel = mw::Kernel::Create(blind, std::nullopt, 0, std::nullopt, {}, lock_height, extra_data);
    mw::MutableKernel mutable_kernel;
    mutable_kernel.Update(kernel);
    tx.mweb_tx.kernels.push_back(mutable_kernel);
    tx.mweb_tx.kernel_offset = Blinds(tx.mweb_tx.kernel_offset).Sub(blind).Total();
    return tx;
}

CScript BareMultisig()
{
    return CScript() << OP_1 << PublicKey::From(SecretKey::Random()).vec() << OP_1 << OP_CHECKMULTISIG;
}

// The mempool suite owns transaction lifecycles. Here, real dry-run admission
// isolates the validation contract; only initial funding is seeded into chainstate.
class MWEBAdmissionTestingSetup : public TestingSetup
{
public:
    explicit MWEBAdmissionTestingSetup(const bool require_standard = true)
        : TestingSetup{CBaseChainParams::REGTEST, {
              require_standard ? "-acceptnonstdtxn=0" : "-acceptnonstdtxn=1",
              "-vbparams=mweb:-1:9223372036854775807:0:0"}},
          m_pool{*m_node.mempool},
          m_coins{m_node.chainman->ActiveChainstate().CoinsTip()},
          m_view{m_coins.GetMWEBCacheView()},
          m_address{PublicKey::From(SecretKey::Random()), PublicKey::From(m_spend_key)}
    {
        SetMockTime(1'601'450'001);
        BOOST_REQUIRE_EQUAL(m_pool.m_require_standard, require_standard);
    }

    test::TxOutput FundMWEB(const CAmount amount = FUNDING_AMOUNT)
    {
        LOCK(cs_main);
        auto output = test::TxOutput::Create(m_sender_key, m_address, amount);
        m_view->AddCoin(0, output.GetOutput());
        m_funded_outputs.push_back(output.GetOutputID());
        return output;
    }

    CMutableTransaction Spend(const test::TxOutput& input, const CAmount fee = MWEB_FEE,
                              const std::vector<PegOutCoin>& pegouts = {}, const size_t num_outputs = 1) const
    {
        const auto spend_key = mw::DeriveOutputSpendKey(m_spend_key,
            mw::DeriveSharedSecret(m_sender_key, m_address, input.GetAmount()));
        test::TxBuilder builder;
        builder.AddInput(input.GetAmount(), spend_key, input.GetBlind(), input.GetOutputID());
        CAmount change = input.GetAmount() - fee;
        for (const auto& pegout : pegouts) change -= pegout.GetAmount();
        if (num_outputs == 0) {
            BOOST_REQUIRE_EQUAL(change, 0);
        } else {
            BOOST_REQUIRE_GE(change, static_cast<CAmount>(num_outputs));
            const CAmount amount = change / num_outputs;
            for (size_t i = 0; i < num_outputs; ++i) {
                const CAmount output_amount = i + 1 == num_outputs ? change : amount;
                builder.AddOutput(output_amount, m_sender_key, m_address);
                change -= output_amount;
            }
        }
        if (pegouts.empty()) {
            builder.AddPlainKernel(fee);
        } else {
            builder.AddPegoutKernel(pegouts, fee);
        }
        return WithMWEB(builder.Build().GetTransaction());
    }

    CMutableTransaction Pegin(const CAmount fee = MWEB_FEE, const std::vector<PegOutCoin>& pegouts = {},
                              const std::optional<int32_t> lock_height = std::nullopt) const
    {
        CAmount change = FUNDING_AMOUNT - fee;
        for (const auto& pegout : pegouts) change -= pegout.GetAmount();
        BOOST_REQUIRE_GT(change, 0);
        const auto output = test::TxOutput::Create(m_sender_key, m_address, change);
        const auto blind = BlindingFactor::Random();
        const auto kernel = mw::Kernel::Create(blind, std::nullopt, fee, FUNDING_AMOUNT, pegouts, lock_height, {});
        return WithMWEB(mw::Transaction::Create(Blinds(output.GetBlind()).Sub(blind).Total(), m_sender_key,
            {}, {output.GetOutput()}, {kernel}));
    }

    // Generate proofs and signatures for the feature-bearing data itself, so a
    // policy test cannot accidentally pass because of broken cryptography.
    CMutableTransaction SpendWithExtraData(const test::TxOutput& coin, const std::vector<uint8_t>& input_data,
                                           const std::vector<uint8_t>& output_data) const
    {
        const auto spend_key = mw::DeriveOutputSpendKey(m_spend_key,
            mw::DeriveSharedSecret(m_sender_key, m_address, coin.GetAmount()));
        const auto input_key = SecretKey::Random();
        mw::MutableInput input{coin.GetOutputID()};
        input.Update(mw::Input::Create(coin.GetOutputID(), coin.GetCommitment(), input_key, spend_key));
        if (!input_data.empty()) {
            *input.features |= mw::Input::EXTRA_DATA_FEATURE_BIT;
            input.extradata = input_data;
            const auto key_hash = SecretKey::FromHash(Hasher().Append(*input.input_pubkey).Append(*input.output_pubkey).hash());
            const auto signing_key = SecretKeys::From(spend_key).Mul(key_hash).Add(input_key).Total();
            input.signature = Schnorr::Sign(signing_key.data(), input.Finalized()->BuildSignedMsg().GetMsgHash());
        }

        const CAmount change = coin.GetAmount() - MWEB_FEE;
        BlindingFactor raw_blind;
        const auto output = mw::Output::Create(&raw_blind, m_sender_key, SecretKey::Random(), m_address, change, output_data);
        const auto kernel_blind = BlindingFactor::Random();
        const auto kernel = mw::Kernel::Create(kernel_blind, std::nullopt, MWEB_FEE, std::nullopt, {}, std::nullopt, {});
        return WithMWEB(mw::Transaction::Create(
            Blinds(Pedersen::BlindSwitch(raw_blind, change)).Sub(coin.GetBlind()).Sub(kernel_blind).Total(),
            Blinds(m_sender_key).Add(input_key).Sub(spend_key).Total(),
            {*input.Finalized()}, {output}, {kernel}));
    }

    CMutableTransaction FundCanonical(CMutableTransaction tx, const CAmount fee = CANONICAL_FEE)
    {
        LOCK(cs_main);
        const COutPoint prevout{InsecureRand256(), 0};
        tx.vin.emplace_back(prevout);
        tx.vin.back().scriptWitness.stack = {WITNESS_STACK_ELEM_OP_TRUE};
        m_coins.AddCoin(prevout, Coin{CTxOut{CTransaction{tx}.GetValueOut() + fee, P2WSH_OP_TRUE}, 0, false}, false);
        m_funded_outpoints.push_back(prevout);
        return tx;
    }

    void CheckUnchanged(const CTransaction& tx)
    {
        LOCK2(cs_main, m_pool.cs);
        BOOST_CHECK_EQUAL(m_pool.size(), 0U);
        BOOST_CHECK(m_pool.mapNextTx.empty());
        BOOST_CHECK(m_pool.mapTxOutputs_MWEB.empty());
        for (const auto& output_id : m_funded_outputs) BOOST_CHECK(m_view->HasCoin(output_id));
        for (const auto& outpoint : m_funded_outpoints) BOOST_CHECK(m_coins.HaveCoin(outpoint));
        for (const auto& output_id : tx.mweb_tx.GetOutputIDs()) BOOST_CHECK(!m_view->HasCoin(output_id));
        m_pool.check(m_coins, m_node.chainman->ActiveChain().Height() + 1);
    }

    void Accept(const CMutableTransaction& tx, const CAmount expected_fee = MWEB_FEE)
    {
        const auto transaction = MakeTransactionRef(tx);
        const auto result = WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(transaction, /*test_accept=*/true));
        BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID, result.m_state.ToString());
        BOOST_REQUIRE(result.m_base_fees.has_value());
        BOOST_CHECK_EQUAL(*result.m_base_fees, expected_fee);
        BOOST_REQUIRE(result.m_mweb_weight.has_value());
        BOOST_CHECK_EQUAL(*result.m_mweb_weight, transaction->mweb_tx.GetMWEBWeight());
        CheckUnchanged(*transaction);
    }

    void Reject(const CMutableTransaction& tx, const TxValidationResult error, const std::string& reason)
    {
        const auto transaction = MakeTransactionRef(tx);
        const auto result = WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(transaction, /*test_accept=*/true));
        BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::INVALID, "Transaction unexpectedly accepted");
        BOOST_CHECK(result.m_state.GetResult() == error);
        BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), reason);
        CheckUnchanged(*transaction);
    }

    void RequireContextFreeValid(const CMutableTransaction& tx) const
    {
        TxValidationState state;
        BOOST_REQUIRE_MESSAGE(MWEB::Node::CheckTransaction(CTransaction{tx}, state), state.ToString());
    }

    CTxMemPool& m_pool;
    CCoinsViewCache& m_coins;
    mw::CoinsViewCache::Ptr m_view;
    SecretKey m_spend_key{SecretKey::Random()};
    SecretKey m_sender_key{SecretKey::Random()};
    StealthAddress m_address;
    std::vector<mw::Hash> m_funded_outputs;
    std::vector<COutPoint> m_funded_outpoints;
};

struct NonstandardMWEBAdmissionTestingSetup : MWEBAdmissionTestingSetup
{
    NonstandardMWEBAdmissionTestingSetup() : MWEBAdmissionTestingSetup{false} {}
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(mweb_admission_tests, MWEBAdmissionTestingSetup)

// A full peg-out may consume all MWEB funds without producing an MWEB change output or canonical transaction data.
BOOST_AUTO_TEST_CASE(full_pegout_needs_no_mweb_change)
{
    const auto funding = FundMWEB();
    const auto tx = Spend(funding, MWEB_FEE, {{FUNDING_AMOUNT - MWEB_FEE, P2WSH_OP_TRUE}}, 0);
    BOOST_REQUIRE(CTransaction{tx}.IsMWEBOnly());
    BOOST_REQUIRE(tx.mweb_tx.outputs.empty());
    Accept(tx);
}

// Carrying MWEB data does not exempt a hybrid from having both canonical inputs and outputs.
BOOST_AUTO_TEST_CASE(hybrid_requires_complete_canonical_shape)
{
    const auto valid = FundCanonical(Pegin());
    auto missing_inputs = valid;
    missing_inputs.vin.clear();
    Reject(missing_inputs, TxValidationResult::TX_CONSENSUS, "bad-txns-vin-empty");
    auto missing_outputs = valid;
    missing_outputs.vout.clear();
    Reject(missing_outputs, TxValidationResult::TX_CONSENSUS, "bad-txns-vout-empty");
    Accept(valid, CANONICAL_FEE + MWEB_FEE);
}

// Canonical duplicate-input checks run before MWEB signature verification, even for an otherwise malformed hybrid.
BOOST_AUTO_TEST_CASE(canonical_sanity_precedes_mweb_verification)
{
    const auto valid = FundCanonical(Pegin());
    auto invalid = valid;
    invalid.vin.push_back(invalid.vin.front());
    invalid.mweb_tx.outputs.front().signature = Signature{};
    Reject(invalid, TxValidationResult::TX_CONSENSUS, "bad-txns-inputs-duplicate");
    Accept(valid, CANONICAL_FEE + MWEB_FEE);
}

// A stripped peg-in cannot enter the mempool; restoring its matching MWEB payload makes it admissible.
BOOST_AUTO_TEST_CASE(stripped_pegin_requires_its_mweb_payload)
{
    const auto valid = FundCanonical(Pegin());
    auto stripped = valid;
    stripped.mweb_tx.SetNull();
    Reject(stripped, TxValidationResult::TX_WITNESS_MUTATED, "pegin-count-mismatch");
    Accept(valid, CANONICAL_FEE + MWEB_FEE);
}

// Multiple peg-ins are standard when every kernel is matched by exactly one canonical peg-in output.
BOOST_AUTO_TEST_CASE(multiple_matching_pegins_are_standard)
{
    const CTransaction first{Pegin()};
    const CTransaction second{Pegin()};
    const auto combined = WithMWEB(Aggregation::Aggregate({first.mweb_tx.m_transaction, second.mweb_tx.m_transaction}));
    const auto tx = FundCanonical(combined);
    BOOST_REQUIRE_EQUAL(tx.vout.size(), 2U);
    BOOST_REQUIRE_EQUAL(tx.mweb_tx.kernels.size(), 2U);
    Accept(tx, CANONICAL_FEE + 2 * MWEB_FEE);
}

// The HogEx marker is only meaningful inside a block and cannot turn a funded transaction into a mempool entry.
BOOST_AUTO_TEST_CASE(hogex_is_not_admitted_as_a_loose_transaction)
{
    CMutableTransaction tx;
    tx.vout.emplace_back(COIN, P2WSH_OP_TRUE);
    tx = FundCanonical(tx);
    tx.m_hogEx = true;
    Reject(tx, TxValidationResult::TX_CONSENSUS, "hogex");
    tx.m_hogEx = false;
    Accept(tx, CANONICAL_FEE);
}

// The cheap MWEB weight limit rejects an oversized transaction before inspecting its deliberately invalid signature.
BOOST_AUTO_TEST_CASE(relay_weight_check_precedes_signature_verification)
{
    const auto funding = FundMWEB();
    const auto oversized = Spend(funding, COIN, {}, RELAY_WEIGHT_LIMIT / mw::STANDARD_OUTPUT_WEIGHT + 1);
    BOOST_REQUIRE_GT(CTransaction{oversized}.mweb_tx.GetMWEBWeight(), RELAY_WEIGHT_LIMIT);
    RequireContextFreeValid(oversized);
    auto invalid = oversized;
    invalid.mweb_tx.outputs.front().signature = Signature{};
    Reject(invalid, TxValidationResult::TX_NOT_STANDARD, "mweb-txn-oversize");
    Accept(Spend(funding));
}

// Input-count limits are checked before duplicate-input and signature validation, without looking up the excess inputs.
BOOST_AUTO_TEST_CASE(relay_input_check_precedes_mweb_body_validation)
{
    const auto funding = FundMWEB();
    const auto valid = Spend(funding);
    auto invalid = valid;
    invalid.mweb_tx.inputs.assign(RELAY_INPUT_LIMIT + 1, valid.mweb_tx.inputs.front());
    invalid.mweb_tx.inputs.front().signature = Signature{};
    Reject(invalid, TxValidationResult::TX_NOT_STANDARD, "mweb-txn-too-many-inputs");
    Accept(valid);
}

// A within-limit invalid signature is a witness mutation, even when the transaction also has a nonstandard peg-out script.
BOOST_AUTO_TEST_CASE(mweb_verification_precedes_script_standardness)
{
    const auto funding = FundMWEB();
    auto tx = Spend(funding, MWEB_FEE, {{COIN, CScript() << OP_TRUE}});
    tx.mweb_tx.kernels.front().signature = Signature{};
    Reject(tx, TxValidationResult::TX_WITNESS_MUTATED, "bad-mweb-txn-invalid-sig");
    Reject(Spend(funding, MWEB_FEE, {{COIN, CScript() << OP_TRUE}}), TxValidationResult::TX_NOT_STANDARD, "scriptpubkey");
}

// Admission verifies input-owner signatures as well as output and kernel signatures, without consuming the real coin.
BOOST_AUTO_TEST_CASE(invalid_input_signature_is_rejected)
{
    const auto valid = Spend(FundMWEB());
    auto invalid = valid;
    invalid.mweb_tx.inputs.front().signature = Signature{};
    Reject(invalid, TxValidationResult::TX_WITNESS_MUTATED, "bad-mweb-txn-invalid-sig");
    Accept(valid);
}

// A corrupted rangeproof is rejected as such after the output is re-signed, so an invalid signature cannot mask the test.
BOOST_AUTO_TEST_CASE(invalid_rangeproof_with_valid_signature_is_rejected)
{
    const auto valid = Spend(FundMWEB());
    auto invalid = valid;
    auto& output = invalid.mweb_tx.outputs.front();
    output.proof = std::make_shared<RangeProof>(std::vector<uint8_t>(RangeProof::SIZE, 0));
    output.signature = Schnorr::Sign(m_sender_key.data(), output.Finalized()->BuildSignedMsg().GetMsgHash());
    BOOST_REQUIRE(Schnorr::BatchVerify({output.Finalized()->BuildSignedMsg()}));
    Reject(invalid, TxValidationResult::TX_WITNESS_MUTATED, "bad-mweb-txn-bulletproof");
    Accept(valid);
}

// Changing only the kernel offset breaks the value-balance proof despite leaving every signature and rangeproof valid.
BOOST_AUTO_TEST_CASE(unbalanced_kernel_offset_is_rejected)
{
    const auto valid = Spend(FundMWEB());
    auto invalid = valid;
    invalid.mweb_tx.kernel_offset = Blinds(invalid.mweb_tx.kernel_offset).Add(BlindingFactor::Random()).Total();
    Reject(invalid, TxValidationResult::TX_WITNESS_MUTATED, "bad-mweb-txn-block-sums");
    Accept(valid);
}

// Changing only the stealth offset breaks the ownership balance without changing the transaction's value balance.
BOOST_AUTO_TEST_CASE(unbalanced_stealth_offset_is_rejected)
{
    const auto valid = Spend(FundMWEB());
    auto invalid = valid;
    invalid.mweb_tx.stealth_offset = Blinds(invalid.mweb_tx.stealth_offset).Add(BlindingFactor::Random()).Total();
    Reject(invalid, TxValidationResult::TX_WITNESS_MUTATED, "bad-mweb-txn-stealth-sums");
    Accept(valid);
}

// Signed extra input data is consensus-valid but nonstandard, independently of the kernel and output feature rules.
BOOST_AUTO_TEST_CASE(extra_input_data_is_nonstandard)
{
    const auto funding = FundMWEB();
    const auto tx = SpendWithExtraData(funding, {1, 2, 3}, {});
    RequireContextFreeValid(tx);
    Reject(tx, TxValidationResult::TX_NOT_STANDARD, "non-standard-mweb-tx");
    Accept(Spend(funding));
}

// An output with a valid proof and signature over extra message data is still rejected by relay standardness.
BOOST_AUTO_TEST_CASE(extra_output_data_is_nonstandard)
{
    const auto funding = FundMWEB();
    const auto tx = SpendWithExtraData(funding, {}, {1, 2, 3});
    RequireContextFreeValid(tx);
    Reject(tx, TxValidationResult::TX_NOT_STANDARD, "non-standard-mweb-tx");
    Accept(Spend(funding));
}

// A peg-out at the canonical dust threshold is accepted; one litoshi less is rejected.
BOOST_AUTO_TEST_CASE(pegout_dust_threshold_is_inclusive)
{
    const auto funding = FundMWEB();
    const CAmount threshold = GetDustThreshold(CTxOut{0, P2WSH_OP_TRUE}, m_pool.m_dust_relay_feerate);
    BOOST_REQUIRE_GT(threshold, 0);
    Reject(Spend(funding, MWEB_FEE, {{threshold - 1, P2WSH_OP_TRUE}}), TxValidationResult::TX_NOT_STANDARD, "dust");
    Accept(Spend(funding, MWEB_FEE, {{threshold, P2WSH_OP_TRUE}}));
}

// Data-carrier peg-outs share the canonical script-size limit, including the OP_RETURN and push-data bytes.
BOOST_AUTO_TEST_CASE(pegout_datacarrier_size_boundary)
{
    const auto funding = FundMWEB();
    BOOST_REQUIRE(m_pool.m_max_datacarrier_bytes.has_value());
    const auto limit = *m_pool.m_max_datacarrier_bytes;
    const CScript at_limit = CScript() << OP_RETURN << std::vector<uint8_t>(limit - 3, 1);
    const CScript too_large = CScript() << OP_RETURN << std::vector<uint8_t>(limit - 2, 1);
    BOOST_REQUIRE_EQUAL(at_limit.size(), limit);
    BOOST_REQUIRE_EQUAL(too_large.size(), limit + 1);
    Reject(Spend(funding, MWEB_FEE, {{0, too_large}}), TxValidationResult::TX_NOT_STANDARD, "scriptpubkey");
    Accept(Spend(funding, MWEB_FEE, {{0, at_limit}}));
}

// Two data-carrier peg-outs are nonstandard even when they are carried by different kernels of an aggregate.
BOOST_AUTO_TEST_CASE(datacarrier_count_spans_all_mweb_kernels)
{
    const auto first = Spend(FundMWEB(), MWEB_FEE, {{0, CScript() << OP_RETURN << OP_1}});
    const auto second = Spend(FundMWEB(), MWEB_FEE, {{0, CScript() << OP_RETURN << OP_2}});
    Accept(first);
    Accept(second);
    const auto aggregate = WithMWEB(Aggregation::Aggregate({CTransaction{first}.mweb_tx.m_transaction, CTransaction{second}.mweb_tx.m_transaction}));
    RequireContextFreeValid(aggregate);
    Reject(aggregate, TxValidationResult::TX_NOT_STANDARD, "multi-op-return");
}

// A hybrid's canonical OP_RETURN and its MWEB data-carrier peg-out count toward the same one-output allowance.
BOOST_AUTO_TEST_CASE(datacarrier_count_spans_canonical_and_mweb_outputs)
{
    auto tx = Pegin(MWEB_FEE, {{0, CScript() << OP_RETURN << OP_1}});
    tx.vout.emplace_back(0, CScript() << OP_RETURN << OP_2);
    tx = FundCanonical(tx);
    RequireContextFreeValid(tx);
    Reject(tx, TxValidationResult::TX_NOT_STANDARD, "multi-op-return");
    tx.vout.pop_back();
    Accept(tx, CANONICAL_FEE + MWEB_FEE);
}

// Disabling data carriers applies to MWEB peg-outs, not just canonical outputs.
BOOST_AUTO_TEST_CASE(datacarrier_policy_applies_to_pegouts)
{
    const auto tx = Spend(FundMWEB(), MWEB_FEE, {{0, CScript() << OP_RETURN << OP_1}});
    RequireContextFreeValid(tx);
    std::string reason;
    BOOST_CHECK(!IsStandardTx(CTransaction{tx}, std::nullopt, true, m_pool.m_dust_relay_feerate, reason));
    BOOST_CHECK_EQUAL(reason, "scriptpubkey");
    Accept(tx);
}

// The bare-multisig policy switch also governs MWEB peg-out destinations.
BOOST_AUTO_TEST_CASE(bare_multisig_policy_applies_to_pegouts)
{
    const auto tx = Spend(FundMWEB(), MWEB_FEE, {{COIN, BareMultisig()}});
    RequireContextFreeValid(tx);
    std::string reason;
    BOOST_CHECK(!IsStandardTx(CTransaction{tx}, m_pool.m_max_datacarrier_bytes, false, m_pool.m_dust_relay_feerate, reason));
    BOOST_CHECK_EQUAL(reason, "bare-multisig");
    Accept(tx);
}

// Peg-out scripts consume the same signature-operation budget as canonical outputs, with the limit itself allowed.
BOOST_AUTO_TEST_CASE(pegout_sigop_cost_limit_is_inclusive)
{
    const auto funding = FundMWEB();
    const CScript script = BareMultisig();
    const unsigned int cost_per_pegout = WITNESS_SCALE_FACTOR * script.GetSigOpCount(false);
    const size_t count = MAX_STANDARD_TX_SIGOPS_COST / cost_per_pegout;
    std::vector<PegOutCoin> pegouts(count, PegOutCoin{10'000, script});
    const auto at_limit = Spend(funding, COIN, pegouts);
    BOOST_REQUIRE_EQUAL(WITNESS_SCALE_FACTOR * GetLegacySigOpCount(CTransaction{at_limit}), MAX_STANDARD_TX_SIGOPS_COST);
    Accept(at_limit, COIN);
    pegouts.emplace_back(10'000, script);
    Reject(Spend(funding, COIN, pegouts), TxValidationResult::TX_NOT_STANDARD, "bad-txns-too-many-sigops");
}

// A hybrid must cover both its canonical relay fee and its MWEB weight charge, even if the peg-in kernel charges no fee.
BOOST_AUTO_TEST_CASE(hybrid_relay_fee_includes_both_weight_components)
{
    const auto probe = FundCanonical(Pegin(0));
    const CTransaction transaction{probe};
    const CAmount minimum = m_pool.m_min_relay_feerate.GetFee(GetVirtualTransactionSize(transaction), transaction.mweb_tx.GetMWEBWeight());
    BOOST_REQUIRE_GT(minimum, m_pool.m_min_relay_feerate.GetFee(GetVirtualTransactionSize(transaction), 0));
    Reject(FundCanonical(Pegin(0), minimum - 1), TxValidationResult::TX_MEMPOOL_POLICY, "min relay fee not met");
    Accept(FundCanonical(Pegin(0), minimum), minimum);
}

// MWEB fees cannot make up for a canonical input shortfall; each side must balance before the fees are combined.
BOOST_AUTO_TEST_CASE(mweb_fees_cannot_subsidize_negative_canonical_fees)
{
    auto tx = Spend(FundMWEB());
    tx.vout.emplace_back(COIN, P2WSH_OP_TRUE);
    tx = FundCanonical(tx, 0);
    ++tx.vout.front().nValue;
    RequireContextFreeValid(tx);
    LOCK(cs_main);
    TxValidationState state;
    CAmount fee{-1};
    BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction{tx}, state, m_coins, 1, fee));
    BOOST_CHECK(state.GetResult() == TxValidationResult::TX_CONSENSUS);
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-in-belowout");
    BOOST_CHECK_EQUAL(fee, -1);
    CheckUnchanged(CTransaction{tx});
}

// A valid MWEB fee can reach MAX_MONEY, but adding one litoshi of canonical fees must reject the combined total.
BOOST_AUTO_TEST_CASE(combined_fee_money_range_boundary)
{
    const auto pure = Spend(FundMWEB(MAX_MONEY), MAX_MONEY, {}, 0);
    RequireContextFreeValid(pure);
    auto hybrid = pure;
    hybrid.vout.emplace_back(COIN, P2WSH_OP_TRUE);
    hybrid = FundCanonical(hybrid, 1);
    RequireContextFreeValid(hybrid);
    LOCK(cs_main);
    TxValidationState valid_state;
    CAmount fee{-1};
    BOOST_REQUIRE(Consensus::CheckTxInputs(CTransaction{pure}, valid_state, m_coins, 1, fee));
    BOOST_CHECK_EQUAL(fee, MAX_MONEY);
    TxValidationState invalid_state;
    fee = -1;
    BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction{hybrid}, invalid_state, m_coins, 1, fee));
    BOOST_CHECK(invalid_state.GetResult() == TxValidationResult::TX_CONSENSUS);
    BOOST_CHECK_EQUAL(invalid_state.GetRejectReason(), "bad-txns-mwebfee-outofrange");
    BOOST_CHECK_EQUAL(fee, -1);
    CheckUnchanged(CTransaction{hybrid});
}

// Input accounting rejects invalid individual kernel fees and out-of-range kernel totals before returning a fee.
BOOST_AUTO_TEST_CASE(kernel_fee_accounting_rejects_invalid_amounts)
{
    const auto valid = Spend(FundMWEB());
    for (const CAmount invalid_fee : {CAmount{-1}, MAX_MONEY + 1}) {
        BOOST_TEST_CONTEXT("kernel fee " << invalid_fee) {
            auto tx = valid;
            tx.mweb_tx.kernels.front().fee = invalid_fee;
            LOCK(cs_main);
            TxValidationState state;
            CAmount fee{-1};
            BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction{tx}, state, m_coins, 1, fee));
            BOOST_CHECK(state.GetResult() == TxValidationResult::TX_CONSENSUS);
            BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-mwebfee-outofrange");
            BOOST_CHECK_EQUAL(fee, -1);
        }
    }
    auto excessive_total = WithExtraKernel(valid);
    excessive_total.mweb_tx.kernels.front().fee = MAX_MONEY;
    excessive_total.mweb_tx.kernels.back().fee = 1;
    LOCK(cs_main);
    TxValidationState state;
    CAmount fee{-1};
    BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction{excessive_total}, state, m_coins, 1, fee));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-mwebfee-outofrange");
    BOOST_CHECK_EQUAL(fee, -1);
    CheckUnchanged(CTransaction{excessive_total});
}

// Every kernel height lock must be satisfied; a pure-MWEB transaction cannot bypass the highest lock through empty vin.
BOOST_AUTO_TEST_CASE(finality_uses_highest_kernel_lock)
{
    const auto transfer = Spend(FundMWEB());
    const auto locked = WithExtraKernel(WithExtraKernel(transfer, 1), 2);
    RequireContextFreeValid(locked);
    BOOST_CHECK(!IsFinalTx(CTransaction{locked}, 1, 0));
    BOOST_CHECK(IsFinalTx(CTransaction{locked}, 2, 0));
    Reject(locked, TxValidationResult::TX_PREMATURE_SPEND, "non-final");
    Accept(WithExtraKernel(WithExtraKernel(transfer, 0), 1));
}

// A satisfied MWEB height lock does not bypass a hybrid's unsatisfied canonical absolute lock time.
BOOST_AUTO_TEST_CASE(hybrid_must_satisfy_canonical_and_kernel_lock_times)
{
    auto tx = FundCanonical(Pegin(MWEB_FEE, {}, 1));
    tx.nLockTime = 1;
    tx.vin.front().nSequence = CTxIn::SEQUENCE_FINAL - 1;
    Reject(tx, TxValidationResult::TX_PREMATURE_SPEND, "non-final");
    tx.nLockTime = 0;
    Accept(tx, CANONICAL_FEE + MWEB_FEE);
}

// A hybrid's canonical relative-height lock is enforced independently of its already-satisfied MWEB kernel lock.
BOOST_AUTO_TEST_CASE(hybrid_must_satisfy_canonical_sequence_locks)
{
    auto tx = FundCanonical(Pegin(MWEB_FEE, {}, 1));
    tx.vin.front().nSequence = 2;
    Reject(tx, TxValidationResult::TX_PREMATURE_SPEND, "non-BIP68-final");
    tx.vin.front().nSequence = 1;
    Accept(tx, CANONICAL_FEE + MWEB_FEE);
}

// A valid MWEB peg-in still requires a valid canonical witness; fixing that witness must make the same transaction admissible.
BOOST_AUTO_TEST_CASE(hybrid_requires_valid_canonical_witness)
{
    const auto valid = FundCanonical(Pegin());
    auto invalid = valid;
    invalid.vin.front().scriptWitness.stack = {{OP_FALSE}};
    RequireContextFreeValid(invalid);
    BOOST_REQUIRE(CTransaction{invalid}.GetHash() == CTransaction{valid}.GetHash());
    BOOST_REQUIRE(CTransaction{invalid}.GetWitnessHash() != CTransaction{valid}.GetWitnessHash());
    Reject(invalid, TxValidationResult::TX_NOT_STANDARD, "non-mandatory-script-verify-flag (Witness program hash mismatch)");
    Accept(valid, CANONICAL_FEE + MWEB_FEE);
}

// A hybrid with only its canonical witness stripped is identified as incomplete witness data and can be retried intact.
BOOST_AUTO_TEST_CASE(hybrid_with_stripped_canonical_witness_is_retryable)
{
    const auto valid = FundCanonical(Pegin());
    auto stripped = valid;
    stripped.vin.front().scriptWitness.SetNull();
    RequireContextFreeValid(stripped);
    Reject(stripped, TxValidationResult::TX_WITNESS_STRIPPED,
        "non-mandatory-script-verify-flag (Witness program was passed an empty witness)");
    Accept(valid, CANONICAL_FEE + MWEB_FEE);
}

// With standardness disabled, a consensus-valid MWEB transaction may exceed the standalone relay weight limit.
BOOST_FIXTURE_TEST_CASE(nonstandard_mode_allows_consensus_valid_large_transactions, NonstandardMWEBAdmissionTestingSetup)
{
    const auto tx = Spend(FundMWEB(), COIN, {}, RELAY_WEIGHT_LIMIT / mw::STANDARD_OUTPUT_WEIGHT + 1);
    RequireContextFreeValid(tx);
    std::string reason;
    BOOST_REQUIRE(!MWEB::Policy::CheckWeight(CTransaction{tx}, reason));
    BOOST_CHECK_EQUAL(reason, "mweb-txn-oversize");
    Accept(tx, COIN);
}

// Extra kernel data is relay policy, not a consensus violation, when nonstandard transactions are explicitly allowed.
BOOST_FIXTURE_TEST_CASE(nonstandard_mode_allows_extra_kernel_data, NonstandardMWEBAdmissionTestingSetup)
{
    const auto tx = WithExtraKernel(Spend(FundMWEB()), std::nullopt, {1, 2, 3});
    RequireContextFreeValid(tx);
    std::string reason;
    BOOST_REQUIRE(!MWEB::Policy::IsStandardTx(CTransaction{tx}, reason));
    BOOST_CHECK_EQUAL(reason, "non-standard-mweb-tx");
    Accept(tx);
}

// Disabling standardness permits valid extra input data while retaining normal coin ownership and fee checks.
BOOST_FIXTURE_TEST_CASE(nonstandard_mode_allows_extra_input_data, NonstandardMWEBAdmissionTestingSetup)
{
    const auto tx = SpendWithExtraData(FundMWEB(), {1, 2, 3}, {});
    RequireContextFreeValid(tx);
    Accept(tx);
}

// Disabling standardness permits extra output messages when their rangeproofs and signatures are valid.
BOOST_FIXTURE_TEST_CASE(nonstandard_mode_allows_extra_output_data, NonstandardMWEBAdmissionTestingSetup)
{
    const auto tx = SpendWithExtraData(FundMWEB(), {}, {1, 2, 3});
    RequireContextFreeValid(tx);
    Accept(tx);
}

// Disabling relay standardness permits a signed nonstandard peg-out script without weakening MWEB consensus validation.
BOOST_FIXTURE_TEST_CASE(nonstandard_mode_allows_nonstandard_pegout_script, NonstandardMWEBAdmissionTestingSetup)
{
    const auto tx = Spend(FundMWEB(), MWEB_FEE, {{COIN, CScript() << OP_TRUE}});
    RequireContextFreeValid(tx);
    Accept(tx);
}

// The hybrid aggregation restriction is policy: unrelated valid kernels are admissible when standardness is disabled.
BOOST_FIXTURE_TEST_CASE(nonstandard_mode_allows_hybrid_aggregation, NonstandardMWEBAdmissionTestingSetup)
{
    const auto tx = FundCanonical(WithExtraKernel(Pegin()));
    RequireContextFreeValid(tx);
    std::string reason;
    BOOST_REQUIRE(!MWEB::Policy::IsStandardTx(CTransaction{tx}, reason));
    BOOST_CHECK_EQUAL(reason, "kernel-mismatch");
    Accept(tx, CANONICAL_FEE + MWEB_FEE);
}

// Allowing nonstandard transactions never allows invalid MWEB signatures or unbalanced commitments.
BOOST_FIXTURE_TEST_CASE(nonstandard_mode_still_enforces_mweb_consensus, NonstandardMWEBAdmissionTestingSetup)
{
    const auto valid = Spend(FundMWEB());
    auto bad_signature = valid;
    bad_signature.mweb_tx.kernels.front().signature = Signature{};
    Reject(bad_signature, TxValidationResult::TX_WITNESS_MUTATED, "bad-mweb-txn-invalid-sig");
    auto bad_balance = valid;
    bad_balance.mweb_tx.kernel_offset = Blinds(bad_balance.mweb_tx.kernel_offset).Add(BlindingFactor::Random()).Total();
    Reject(bad_balance, TxValidationResult::TX_WITNESS_MUTATED, "bad-mweb-txn-block-sums");
    Accept(valid);
}

BOOST_AUTO_TEST_SUITE_END()
