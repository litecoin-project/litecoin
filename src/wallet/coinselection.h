// Copyright (c) 2017-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_COINSELECTION_H
#define BITCOIN_WALLET_COINSELECTION_H

#include <consensus/amount.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/address.h>
#include <script/standard.h>
#include <wallet/utxo.h>

#include <optional>

enum class TxType {
    // A traditional LTC->LTC transaction with no MWEB components.
    // INPUTS: LTC inputs only.
    // KERNELS: None.
    // OUTPUTS: LTC outputs only.
    // CHANGE: LTC change only.
    // FEES: All fees must be included in the LTC transaction.
    LTC_TO_LTC,
    // A pure MWEB->MWEB transaction.
    // INPUTS: MWEB inputs only.
    // OUTPUTS: MWEB outputs only.
    // CHANGE: MWEB change only.
    // FEES: All fees must be included in the transaction's kernel(s).
    MWEB_TO_MWEB,
    // A LTC->MWEB pegin transaction.
    // INPUTS: At least one LTC input, but could also include MWEB inputs.
    // KERNELS: At least one kernel with a peg-in amount.
    // OUTPUTS: At least one LTC output with a peg-in script. At least one MWEB output.
    // CHANGE: Could include MWEB change or explicit LTC change.
    // FEES: Split between layers. LTC fee is paid on the LTC transaction (CalcLTCFee, via LTC input/output delta),
    //       and MWEB fee is paid in kernel(s) (CalcMWEBFee, funded by pegin amount and/or MWEB inputs).
    PEGIN,
    // An MWEB->LTC pegout transaction.
    // INPUTS: MWEB inputs only.
    // KERNELS: At least one kernel with a pegout script. Kernel(s) do not contain a pegin amount.
    // OUTPUTS: LTC outputs will be created by miners for each pegout script in the kernel. Could optionally contain MWEB outputs.
    // CHANGE: MWEB change by default; explicit LTC change is represented as an additional pegout.
    // FEES: All fees must be included in the transaction's kernel(s).
    PEGOUT,
    // A LTC->MWEB->LTC pegin and pegout in the same transaction.
    // Created when sending to a LTC address where the wallet only has enough available balance if we include inputs from both LTC and the MWEB.
    // INPUTS: At least one LTC input, but could also include MWEB inputs.
    // KERNELS: At least one kernel with a pegout script. At least one kernel with a pegin amount. Typically, a single kernel used which contains both. 
    // OUTPUTS: At least one LTC output with a peg-in script. Could include additional LTC outputs.
    // CHANGE: Could include MWEB change or explicit LTC change represented as an additional pegout.
    // FEES: Split between layers. LTC fee is paid on the LTC transaction (CalcLTCFee, including hogex input bytes),
    //       and MWEB fee is paid in kernel(s) (CalcMWEBFee, including pegout output bytes and kernel weight).
    PEGIN_PEGOUT
};

namespace wallet {
//! lower bound for randomly-chosen target change amount
static constexpr CAmount CHANGE_LOWER{50000};
//! upper bound for randomly-chosen target change amount
static constexpr CAmount CHANGE_UPPER{1000000};

// Add some waste for every MWEB input so that we minimize the number of MWEB inputs consumed.
static constexpr CAmount MWEB_INPUT_WASTE{1};

enum class TxSizeType {
    BYTES,
    VBYTES,
    WEIGHT,
    MWEB_WEIGHT
};

/** Change parameters for one iteration of Coin Selection. */
struct ChangeParams {
    /** Mininmum change to target in Knapsack solver: select coins to cover the payment and
     * at least this value of change. */
    CAmount m_min_change_target{0};
    /** Minimum amount for creating a change output.
     * If change budget is smaller than min_change then we forgo creation of change output.
     */
    CAmount min_viable_change{0};
    /** Cost of creating the change output. */
    CAmount m_change_fee{0};
    /** Cost of creating the change output + cost of spending the change output in the future. */
    CAmount m_cost_of_change{0};
};

/** Parameters for one iteration of Coin Selection. */
struct CoinSelectionParams {
    /** Randomness to use in the context of coin selection. */
    FastRandomContext& rng_fast;
    /** Change-related parameters. */
    ChangeParams m_change_params;
    /** The targeted feerate of the transaction being built. */
    CFeeRate m_effective_feerate;
    /** The feerate estimate used to estimate an upper bound on what should be sufficient to spend
     * the change output sometime in the future. */
    CFeeRate m_long_term_feerate;
    /** If the cost to spend a change output at the discard feerate exceeds its value, drop it to fees. */
    CFeeRate m_discard_feerate;
    /** Indicate that we are subtracting the fee from outputs */
    bool m_subtract_fee_outputs = false;
    /** When true, always spend all (up to OUTPUT_GROUP_MAX_ENTRIES) or none of the outputs
     * associated with the same address. This helps reduce privacy leaks resulting from address
     * reuse. Dust outputs are not eligible to be added to output groups and thus not considered. */
    bool m_avoid_partial_spends = false;
    /** The tx type (LTC, MWEB, pegin, pegout, pegin_pegout) */
    TxType m_tx_type{TxType::LTC_TO_LTC};

    CoinSelectionParams(FastRandomContext& rng_fast, ChangeParams change_params, CFeeRate effective_feerate,
                        CFeeRate long_term_feerate, CFeeRate discard_feerate, bool avoid_partial, TxType tx_type)
        : rng_fast{rng_fast},
          m_change_params(std::move(change_params)),
          m_effective_feerate(effective_feerate),
          m_long_term_feerate(long_term_feerate),
          m_discard_feerate(discard_feerate),
          m_avoid_partial_spends(avoid_partial),
          m_tx_type(tx_type)
    {
    }
    CoinSelectionParams(FastRandomContext& rng_fast)
        : rng_fast{rng_fast} {}
};

/** Parameters for filtering which OutputGroups we may use in coin selection.
 * We start by being very selective and requiring multiple confirmations and
 * then get more permissive if we cannot fund the transaction. */
struct CoinEligibilityFilter
{
    /** Minimum number of confirmations for outputs that we sent to ourselves.
     * We may use unconfirmed UTXOs sent from ourselves, e.g. change outputs. */
    const int conf_mine;
    /** Minimum number of confirmations for outputs received from a different wallet. */
    const int conf_theirs;
    /** Maximum number of unconfirmed ancestors aggregated across all UTXOs in an OutputGroup. */
    const uint64_t max_ancestors;
    /** Maximum number of descendants that a single UTXO in the OutputGroup may have. */
    const uint64_t max_descendants;
    /** When avoid_reuse=true and there are full groups (OUTPUT_GROUP_MAX_ENTRIES), whether or not to use any partial groups.*/
    const bool m_include_partial_groups{false};

    CoinEligibilityFilter(int conf_mine, int conf_theirs, uint64_t max_ancestors) : conf_mine(conf_mine), conf_theirs(conf_theirs), max_ancestors(max_ancestors), max_descendants(max_ancestors) {}
    CoinEligibilityFilter(int conf_mine, int conf_theirs, uint64_t max_ancestors, uint64_t max_descendants) : conf_mine(conf_mine), conf_theirs(conf_theirs), max_ancestors(max_ancestors), max_descendants(max_descendants) {}
    CoinEligibilityFilter(int conf_mine, int conf_theirs, uint64_t max_ancestors, uint64_t max_descendants, bool include_partial) : conf_mine(conf_mine), conf_theirs(conf_theirs), max_ancestors(max_ancestors), max_descendants(max_descendants), m_include_partial_groups(include_partial) {}
};

/** A group of UTXOs paid to the same output script. */
struct OutputGroup
{
    /** The list of UTXOs contained in this output group. */
    std::vector<AnyWalletUTXO> m_outputs;
    /** Whether the UTXOs were sent by the wallet to itself. This is relevant because we may want at
     * least a certain number of confirmations on UTXOs received from outside wallets while trusting
     * our own UTXOs more. */
    bool m_from_me{true};
    /** The total value of the UTXOs in sum. */
    CAmount m_value{0};
    /** The minimum number of confirmations the UTXOs in the group have. Unconfirmed is 0. */
    int m_depth{999};
    /** The aggregated count of unconfirmed ancestors of all UTXOs in this
     * group. Not deduplicated and may overestimate when ancestors are shared. */
    size_t m_ancestors{0};
    /** The maximum count of descendants of a single UTXO in this output group. */
    size_t m_descendants{0};
    /** The value of the UTXOs after deducting the cost of spending them at the effective feerate. */
    CAmount effective_value{0};
    /** The fee to spend these UTXOs at the effective feerate. */
    CAmount fee{0};
    /** The target feerate of the transaction we're trying to build. */
    CFeeRate m_effective_feerate{0};
    /** The fee to spend these UTXOs at the long term feerate. */
    CAmount long_term_fee{0};
    /** The feerate for spending a created change output eventually (i.e. not urgently, and thus at
     * a lower feerate). Calculated using long term fee estimate. This is used to decide whether
     * it could be economical to create a change output. */
    CFeeRate m_long_term_feerate{0};
    /** Indicate that we are subtracting the fee from outputs.
     * When true, the value that is used for coin selection is the UTXO's real value rather than effective value */
    bool m_subtract_fee_outputs{false};

    OutputGroup() {}
    OutputGroup(const CoinSelectionParams& params) :
        m_effective_feerate(params.m_effective_feerate),
        m_long_term_feerate(params.m_long_term_feerate),
        m_subtract_fee_outputs(params.m_subtract_fee_outputs)
    {}

    void Insert(const AnyWalletUTXO& output, size_t ancestors, size_t descendants, bool positive_only);
    bool EligibleForSpending(const CoinEligibilityFilter& eligibility_filter, const TxType& tx_type) const;
    CAmount GetSelectionAmount() const;

    bool IsMWEB() const noexcept
    {
        return !m_outputs.empty() && m_outputs.front().IsMWEB();
    }

    CAmount GetWaste() const noexcept
    {
        if (IsMWEB()) return MWEB_INPUT_WASTE * m_outputs.size();
        return fee - long_term_fee;
    }
};

/** Compute the waste for this result given the cost of change
 * and the opportunity cost of spending these inputs now vs in the future.
 * If change exists, waste = change_cost + inputs * (effective_feerate - long_term_feerate)
 * If no change, waste = excess + inputs * (effective_feerate - long_term_feerate)
 * where excess = selected_effective_value - target
 * change_cost = effective_feerate * change_output_size + long_term_feerate * change_spend_size
 *
 * Note this function is separate from SelectionResult for the tests.
 *
 * @param[in] inputs The selected inputs
 * @param[in] change_cost The cost of creating change and spending it in the future.
 *                        Only used if there is change, in which case it must be positive.
 *                        Must be 0 if there is no change.
 * @param[in] target The amount targeted by the coin selection algorithm.
 * @param[in] use_effective_value Whether to use the input's effective value (when true) or the real value (when false).
 * @return The waste
 */
[[nodiscard]] CAmount GetSelectionWaste(const std::set<AnyWalletUTXO>& inputs, CAmount change_cost, CAmount target, bool use_effective_value = true);


/** Choose a random change target for each transaction to make it harder to fingerprint the Core
 * wallet based on the change output values of transactions it creates.
 * Change target covers at least change fees and adds a random value on top of it.
 * The random value is between 50ksat and min(2 * payment_value, 1milsat)
 * When payment_value <= 25ksat, the value is just 50ksat.
 *
 * Making change amounts similar to the payment value may help disguise which output(s) are payments
 * are which ones are change. Using double the payment value may increase the number of inputs
 * needed (and thus be more expensive in fees), but breaks analysis techniques which assume the
 * coins selected are just sufficient to cover the payment amount ("unnecessary input" heuristic).
 *
 * @param[in]   payment_value   Average payment value of the transaction output(s).
 * @param[in]   change_fee      Fee for creating a change output.
 */
[[nodiscard]] CAmount GenerateChangeTarget(const CAmount payment_value, const CAmount change_fee, FastRandomContext& rng);

enum class SelectionAlgorithm : uint8_t
{
    BNB = 0,
    KNAPSACK = 1,
    SRD = 2,
    MANUAL = 3,
};

std::string GetAlgorithmName(const SelectionAlgorithm algo);

struct SelectionResult
{
private:
    /** Set of inputs selected by the algorithm to use in the transaction */
    std::set<AnyWalletUTXO> m_selected_inputs;
    /** The target the algorithm selected for. Equal to the recipient amount plus non-input fees */
    CAmount m_target;
    /** The algorithm used to produce this result */
    SelectionAlgorithm m_algo;
    /** Whether the input values for calculations should be the effective value (true) or normal value (false) */
    bool m_use_effective{false};
    /** The computed waste */
    std::optional<CAmount> m_waste;

public:
    explicit SelectionResult(const CAmount target, SelectionAlgorithm algo)
        : m_target(target), m_algo(algo) {}

    SelectionResult() = delete;

    /** Get the sum of the input values */
    [[nodiscard]] CAmount GetSelectedValue() const;

    [[nodiscard]] CAmount GetSelectedEffectiveValue() const;

    void Clear();

    void AddInput(const OutputGroup& group);

    /** Calculates and stores the waste for this selection via GetSelectionWaste */
    void ComputeAndSetWaste(const CAmount min_viable_change, const CAmount change_cost, const CAmount change_fee);
    [[nodiscard]] CAmount GetWaste() const;

    void Merge(const SelectionResult& other);

    /** Get m_selected_inputs */
    const std::set<AnyWalletUTXO>& GetInputSet() const;
    /** Get the vector of COutputs that will be used to fill in a CTransaction's vin */
    std::vector<AnyWalletUTXO> GetShuffledInputVector() const;

    bool operator<(SelectionResult other) const;

    /** Get the amount for the change output after paying needed fees.
     *
     * The change amount is not 100% precise due to discrepancies in fee calculation.
     * The final change amount (if any) should be corrected after calculating the final tx fees.
     * When there is a discrepancy, most of the time the final change would be slightly bigger than estimated.
     *
     * Following are the possible factors of discrepancy:
     *  + non-input fees always include segwit flags
     *  + input fee estimation always include segwit stack size
     *  + input fees are rounded individually and not collectively, which leads to small rounding errors
     *  - input counter size is always assumed to be 1vbyte
     *
     * @param[in]  min_viable_change  Minimum amount for change output, if change would be less then we forgo change
     * @param[in]  change_fee         Fees to include change output in the tx
     * @returns Amount for change output, 0 when there is no change.
     *
     */
    CAmount GetChange(const CAmount min_viable_change, const CAmount change_fee) const;

    CAmount GetTarget() const { return m_target; }

    SelectionAlgorithm GetAlgo() const { return m_algo; }
};

std::optional<SelectionResult> SelectCoinsBnB(std::vector<OutputGroup>& utxo_pool, const CAmount& selection_target, const CAmount& cost_of_change);

/** Select coins by Single Random Draw. OutputGroups are selected randomly from the eligible
 * outputs until the target is satisfied
 *
 * @param[in]  utxo_pool    The positive effective value OutputGroups eligible for selection
 * @param[in]  target_value The target value to select for
 * @returns If successful, a SelectionResult, otherwise, std::nullopt
 */
std::optional<SelectionResult> SelectCoinsSRD(const std::vector<OutputGroup>& utxo_pool, CAmount target_value, FastRandomContext& rng);

// Original coin selection algorithm as a fallback
std::optional<SelectionResult> KnapsackSolver(std::vector<OutputGroup>& groups, const CAmount& nTargetValue,
                                              CAmount change_target, FastRandomContext& rng);
} // namespace wallet

#endif // BITCOIN_WALLET_COINSELECTION_H
