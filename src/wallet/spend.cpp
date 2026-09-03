// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <interfaces/chain.h>
#include <policy/policy.h>
#include <script/signingprovider.h>
#include <util/check.h>
#include <util/fees.h>
#include <util/moneystr.h>
#include <util/rbf.h>
#include <util/trace.h>
#include <util/translation.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>
#include <wallet/receive.h>
#include <wallet/reserve.h>
#include <wallet/spend.h>
#include <wallet/transaction.h>
#include <wallet/txbuilder.h>
#include <wallet/wallet.h>

#include <cmath>

using interfaces::FoundBlock;

namespace wallet {
static constexpr size_t OUTPUT_GROUP_MAX_ENTRIES{100};

// Consensus freezes a specific MWEB output; never make it available for spending.
static bool IsFrozenMWEBOutput(const mw::Hash& output_id)
{
    const auto& frozen_outputs = Params().GetConsensus().frozen_mweb_output_ids;
    return std::find(frozen_outputs.begin(), frozen_outputs.end(), uint256(output_id.vec())) != frozen_outputs.end();
}

int CalculateMaximumSignedInputSize(const CTxOut& txout, const COutPoint outpoint, const SigningProvider* provider, const CCoinControl* coin_control)
{
    CMutableTransaction txn;
    txn.vin.push_back(CTxIn(outpoint));
    if (!provider || !DummySignInput(*provider, txn.vin[0], txout, coin_control)) {
        return -1;
    }
    return GetVirtualTransactionInputSize(txn.vin[0]);
}

int CalculateMaximumSignedInputSize(const CTxOut& txout, const CWallet* wallet, const CCoinControl* coin_control)
{
    const std::unique_ptr<SigningProvider> provider = wallet->GetSolvingProvider(txout.scriptPubKey);
    return CalculateMaximumSignedInputSize(txout, COutPoint(), provider.get(), coin_control);
}

// txouts needs to be in the order of tx.vin
TxSize CalculateMaximumSignedTxSize(const CTransaction &tx, const CWallet *wallet, const std::vector<CTxOut>& txouts, const CCoinControl* coin_control)
{
    CMutableTransaction txNew(tx);
    if (!wallet->DummySignTx(txNew, txouts, coin_control)) {
        return TxSize{-1, -1};
    }
    CTransaction ctx(txNew);
    int64_t vsize = GetVirtualTransactionSize(ctx);
    int64_t weight = GetTransactionWeight(ctx);
    return TxSize{vsize, weight};
}

TxSize CalculateMaximumSignedTxSize(const CTransaction &tx, const CWallet *wallet, const CCoinControl* coin_control)
{
    std::vector<CTxOut> txouts;
    // Look up the inputs. The inputs are either in the wallet, or in coin_control.
    for (const CTxIn& input : tx.vin) {
        const auto mi = wallet->mapWallet.find(input.prevout.hash);
        // Can not estimate size without knowing the input details
        if (mi != wallet->mapWallet.end()) {
            assert(input.prevout.n < mi->second.tx->vout.size());
            txouts.emplace_back(mi->second.tx->vout.at(input.prevout.n));
        } else if (coin_control) {
            AnyOutput output;
            if (!coin_control->GetExternalOutput(input.prevout, output)) {
                return TxSize{-1, -1};
            }
            txouts.emplace_back(output.GetTxOut());
        } else {
            return TxSize{-1, -1};
        }
    }
    return CalculateMaximumSignedTxSize(tx, wallet, txouts, coin_control);
}

size_t CoinsResult::Size() const
{
    size_t size{0};
    for (const auto& it : coins) {
        size += it.second.size();
    }
    return size;
}

std::vector<AnyWalletUTXO> CoinsResult::All() const
{
    std::vector<AnyWalletUTXO> all;
    all.reserve(coins.size());
    for (const auto& it : coins) {
        all.insert(all.end(), it.second.begin(), it.second.end());
    }
    return all;
}

const AnyWalletUTXO* CoinsResult::Find(const AnyOutputID& output_id) const
{
    for (const auto& it : coins) {
        for (const AnyWalletUTXO& coin : it.second) {
            if (coin.GetID() == output_id) {
                return &coin;
            }
        }
    }

    return nullptr;
}

void CoinsResult::Clear() {
    coins.clear();
}

void CoinsResult::Erase(const std::set<AnyOutputID>& coins_to_remove)
{
    for (auto& [type, vec] : coins) {
        auto remove_it = std::remove_if(vec.begin(), vec.end(), [&](const AnyWalletUTXO& coin) {
            return coins_to_remove.count(coin.GetID()) == 1;
        });
        vec.erase(remove_it, vec.end());
    }
}

void CoinsResult::Shuffle(FastRandomContext& rng_fast)
{
    for (auto& it : coins) {
        ::Shuffle(it.second.begin(), it.second.end(), rng_fast);
    }
}

void CoinsResult::Add(OutputType type, const AnyWalletUTXO& out)
{
    coins[type].emplace_back(out);
}

static OutputType GetOutputType(TxoutType type, bool is_from_p2sh)
{
    switch (type) {
        case TxoutType::WITNESS_V1_TAPROOT:
            return OutputType::BECH32M;
        case TxoutType::WITNESS_V0_KEYHASH:
        case TxoutType::WITNESS_V0_SCRIPTHASH:
            if (is_from_p2sh) return OutputType::P2SH_SEGWIT;
            else return OutputType::BECH32;
        case TxoutType::SCRIPTHASH:
        case TxoutType::PUBKEYHASH:
            return OutputType::LEGACY;
        default:
            return OutputType::UNKNOWN;
    }
}

CoinsResult AvailableCoins(const CWallet& wallet,
                           const CCoinControl* coinControl,
                           std::optional<CFeeRate> feerate,
                           const CAmount& nMinimumAmount,
                           const CAmount& nMaximumAmount,
                           const CAmount& nMinimumSumAmount,
                           const uint64_t nMaximumCount,
                           bool only_spendable)
{
    AssertLockHeld(wallet.cs_wallet);

    CoinsResult result;
    // Either the WALLET_FLAG_AVOID_REUSE flag is not set (in which case we always allow), or we default to avoiding, and only in the case where
    // a coin control object is provided, and has the avoid address reuse flag set to false, do we allow already used addresses
    bool allow_used_addresses = !wallet.IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE) || (coinControl && !coinControl->m_avoid_address_reuse);
    const int min_depth = {coinControl ? coinControl->m_min_depth : DEFAULT_MIN_DEPTH};
    const int max_depth = {coinControl ? coinControl->m_max_depth : DEFAULT_MAX_DEPTH};
    const bool only_safe = {coinControl ? !coinControl->m_include_unsafe_inputs : true};

    std::set<uint256> trusted_parents;
    for (const auto& entry : wallet.mapWallet)
    {
        const CWalletTx& wtx = entry.second;

        if (wallet.IsTxImmature(wtx))
            continue;

        int nDepth = wallet.GetTxDepthInMainChain(wtx);
        if (nDepth < 0)
            continue;

        // We should not consider coins which aren't at least in our mempool
        // It's possible for these to be conflicted via ancestors which we may never be able to detect
        if (nDepth == 0 && !wtx.InMempool())
            continue;

        bool safeTx = CachedTxIsTrusted(wallet, wtx, trusted_parents);

        // We should not consider coins from transactions that are replacing
        // other transactions.
        //
        // Example: There is a transaction A which is replaced by bumpfee
        // transaction B. In this case, we want to prevent creation of
        // a transaction B' which spends an output of B.
        //
        // Reason: If transaction A were initially confirmed, transactions B
        // and B' would no longer be valid, so the user would have to create
        // a new transaction C to replace B'. However, in the case of a
        // one-block reorg, transactions B' and C might BOTH be accepted,
        // when the user only wanted one of them. Specifically, there could
        // be a 1-block reorg away from the chain where transactions A and C
        // were accepted to another chain where B, B', and C were all
        // accepted.
        if (nDepth == 0 && wtx.mapValue.count("replaces_txid")) {
            safeTx = false;
        }

        // Similarly, we should not consider coins from transactions that
        // have been replaced. In the example above, we would want to prevent
        // creation of a transaction A' spending an output of A, because if
        // transaction B were initially confirmed, conflicting with A and
        // A', we wouldn't want to the user to create a transaction D
        // intending to replace A', but potentially resulting in a scenario
        // where A, A', and D could all be accepted (instead of just B and
        // D, or just A and A' like the user would want).
        if (nDepth == 0 && wtx.mapValue.count("replaced_by_txid")) {
            safeTx = false;
        }

        if (only_safe && !safeTx) {
            continue;
        }

        if (nDepth < min_depth || nDepth > max_depth) {
            continue;
        }

        bool tx_from_me = CachedTxIsFromMe(wallet, wtx, ISMINE_ALL);
        
        for (const AnyOutputID& output_id : wtx.GetOutputIDs(OutputIdMode::WALLET_OUTPUTS)) {
            if (output_id.IsMWEB() && IsFrozenMWEBOutput(output_id.ToMWEB())) {
                continue;
            }

            if (coinControl) {
                if ((output_id.IsMWEB() && coinControl->fPegIn) || (!output_id.IsMWEB() && coinControl->fPegOut)) {
                    continue;
                }

                if (coinControl->HasSelected() && !coinControl->m_allow_other_inputs && !coinControl->IsSelected(output_id)) {
                    continue;
                }
            }
            
            CAmount value = wallet.GetValue(wtx, output_id);
            if (value < nMinimumAmount || value > nMaximumAmount)
                continue;

            if (wallet.IsLockedCoin(output_id) && !(coinControl && coinControl->IsSelected(output_id)))
                continue;

            if (wallet.IsSpent(output_id))
                continue;

            isminetype mine = wallet.IsMine(output_id);

            if (mine == ISMINE_NO) {
                continue;
            }

            if (!allow_used_addresses && wallet.IsSpentKey(wtx, output_id)) {
                continue;
            }

            if (output_id.IsMWEB()) {
                const bool spendable = (mine & ISMINE_SPENDABLE) != ISMINE_NO;
                const bool solvable = spendable || (mine & ISMINE_WATCH_ONLY) != ISMINE_NO;
                if (!spendable && only_spendable) {
                    continue;
                }

                mw::WalletCoin mweb_coin;
                if (!wallet.GetMWEBWalletCoin(output_id.ToMWEB(), mweb_coin)) {
                    continue;
                }

                StealthAddress address;
                if (!wallet.GetMWWallet()->GetStealthAddress(mweb_coin, address)) {
                    continue;
                }

                MwebWalletUTXO mweb_utxo{mweb_coin, nDepth, address, spendable, solvable, tx_from_me, wtx.GetHash()};
                result.Add(OutputType::MWEB, mweb_utxo);
            } else {
                CTxOut txout = wtx.tx->GetOutput(output_id).GetTxOut();
                std::unique_ptr<SigningProvider> provider = wallet.GetSolvingProvider(txout.scriptPubKey);

                int input_bytes = CalculateMaximumSignedInputSize(txout, COutPoint(), provider.get(), coinControl);
                // Because CalculateMaximumSignedInputSize just uses ProduceSignature and makes a dummy signature,
                // it is safe to assume that this input is solvable if input_bytes is greater -1.
                bool solvable = input_bytes > -1;
                bool spendable = ((mine & ISMINE_SPENDABLE) != ISMINE_NO) || (((mine & ISMINE_WATCH_ONLY) != ISMINE_NO) && (coinControl && coinControl->fAllowWatchOnly && solvable));

                // Filter by spendable outputs only
                if (!spendable && only_spendable) continue;

                // If the Output is P2SH and spendable, we want to know if it is
                // a P2SH (legacy) or one of P2SH-P2WPKH, P2SH-P2WSH (P2SH-Segwit). We can determine
                // this from the redeemScript. If the Output is not spendable, it will be classified
                // as a P2SH (legacy), since we have no way of knowing otherwise without the redeemScript
                CScript script;
                bool is_from_p2sh{false};
                if (txout.scriptPubKey.IsPayToScriptHash() && solvable) {
                    CTxDestination destination;
                    if (!ExtractDestination(txout.scriptPubKey, destination))
                        continue;
                    const CScriptID& hash = CScriptID(std::get<ScriptHash>(destination));
                    if (!provider->GetCScript(hash, script))
                        continue;
                    is_from_p2sh = true;
                } else {
                    script = txout.scriptPubKey;
                }

                CWalletUTXO coin(output_id.ToOutPoint(), txout, nDepth, input_bytes, spendable, solvable, safeTx, wtx.GetTxTime(), tx_from_me, feerate);

                // When parsing a scriptPubKey, Solver returns the parsed pubkeys or hashes (depending on the script)
                // We don't need those here, so we are leaving them in return_values_unused
                std::vector<std::vector<uint8_t>> return_values_unused;
                TxoutType type;
                type = Solver(script, return_values_unused);
                result.Add(GetOutputType(type, is_from_p2sh), coin);
            }

            // Cache total amount as we go
            result.total_amount += value;
            // Checks the sum amount of all UTXO's.
            if (nMinimumSumAmount != MAX_MONEY) {
                if (result.total_amount >= nMinimumSumAmount) {
                    return result;
                }
            }

            // Checks the maximum number of UTXO's.
            if (nMaximumCount > 0 && result.Size() >= nMaximumCount) {
                return result;
            }
        }
    }

    return result;
}

CoinsResult AvailableCoinsListUnspent(const CWallet& wallet, const CCoinControl* coinControl, const CAmount& nMinimumAmount, const CAmount& nMaximumAmount, const CAmount& nMinimumSumAmount, const uint64_t nMaximumCount)
{
    return AvailableCoins(wallet, coinControl, /*feerate=*/ std::nullopt, nMinimumAmount, nMaximumAmount, nMinimumSumAmount, nMaximumCount, /*only_spendable=*/false);
}

CAmount GetAvailableBalance(const CWallet& wallet, const CCoinControl* coinControl)
{
    LOCK(wallet.cs_wallet);
    return AvailableCoins(wallet, coinControl,
            /*feerate=*/ std::nullopt,
            /*nMinimumAmount=*/ 1,
            /*nMaximumAmount=*/ MAX_MONEY,
            /*nMinimumSumAmount=*/ MAX_MONEY,
            /*nMaximumCount=*/ 0
    ).total_amount;
}

bool FindNonChangeParentOutputDestination(const CWallet& wallet, const CWalletTx& wtx, const AnyOutputID& output_id, CTxDestination& dest)
{
    AssertLockHeld(wallet.cs_wallet);
    const CWalletTx* ptx = &wtx;
    AnyOutputID id = output_id;
    while (OutputIsChange(wallet, *ptx, id) && ptx->GetInputs().size() > 0) {
        AnyInput input = ptx->GetInputs().front();
        const CWalletTx* prev_wtx = wallet.FindPrevTx(input);
        if (prev_wtx == nullptr || !wallet.IsMine(input.GetID())) {
            break;
        }
        ptx = prev_wtx;
        id = input.GetID();
    }
    return wallet.ExtractOutputDestination(*ptx, id, dest);
}

bool FindNonChangeParentOutputDestination(const CWallet& wallet, const uint256& tx_hash, const AnyOutputID& output_id, CTxDestination& dest)
{
    AssertLockHeld(wallet.cs_wallet);
    return FindNonChangeParentOutputDestination(wallet, *wallet.GetWalletTx(tx_hash), output_id, dest);
}

std::map<CTxDestination, std::vector<AnyWalletUTXO>> ListCoins(const CWallet& wallet)
{
    AssertLockHeld(wallet.cs_wallet);

    std::map<CTxDestination, std::vector<AnyWalletUTXO>> result;

    for (AnyWalletUTXO& coin : AvailableCoinsListUnspent(wallet).All()) {
        if (coin.IsSpendable() || (wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) && coin.IsSolvable())) {
            CTxDestination address;
            if (FindNonChangeParentOutputDestination(wallet, coin.GetTxHash(), coin.GetID(), address)) {
                result[address].emplace_back(std::move(coin));
            }
        }
    }

    std::vector<AnyOutputID> lockedCoins;
    wallet.ListLockedCoins(lockedCoins);
    // Include watch-only for LegacyScriptPubKeyMan wallets without private keys
    const bool include_watch_only = wallet.GetLegacyScriptPubKeyMan() && wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
    const isminetype is_mine_filter = include_watch_only ? ISMINE_WATCH_ONLY : ISMINE_SPENDABLE;
    for (const AnyOutputID& output_id : lockedCoins) {
        const CWalletTx* wtx = wallet.FindWalletTx(output_id);
        if (wtx != nullptr) {
            int depth = wallet.GetTxDepthInMainChain(*wtx);
            if (depth >= 0 && wallet.IsMine(output_id) == is_mine_filter) {
                CTxDestination address;
                if (FindNonChangeParentOutputDestination(wallet, *wtx, output_id, address)) {
                    if (output_id.IsMWEB()) {
                        mw::WalletCoin coin;
                        if (wallet.GetMWEBWalletCoin(output_id.ToMWEB(), coin) && coin.IsMine()) {
                            StealthAddress stealth_address;
                            wallet.GetMWWallet()->GetStealthAddress(coin, stealth_address);
                            result[address].emplace_back(MwebWalletUTXO{coin, depth, stealth_address, /*spendable=*/true, /*solvable=*/true, CachedTxIsFromMe(wallet, *wtx, ISMINE_ALL), wtx->GetHash()});
                        }
                    } else {
                        const CTxOut& txout = wtx->tx->vout[output_id.ToOutPoint().n];
                        result[address].emplace_back(
                            CWalletUTXO(output_id.ToOutPoint(), txout, depth, CalculateMaximumSignedInputSize(txout, &wallet, /*coin_control=*/nullptr), /*spendable=*/true, /*solvable=*/true, /*safe=*/false, wtx->GetTxTime(), CachedTxIsFromMe(wallet, *wtx, ISMINE_ALL)));
                    }
                }
            }
        }
    }

    return result;
}

std::vector<OutputGroup> GroupOutputs(const CWallet& wallet, const std::vector<AnyWalletUTXO>& outputs, const CoinSelectionParams& coin_sel_params, const CoinEligibilityFilter& filter, bool positive_only)
{
    std::vector<OutputGroup> groups_out;

    if (!coin_sel_params.m_avoid_partial_spends) {
        // Allowing partial spends  means no grouping. Each CWalletUTXO gets its own OutputGroup.
        for (const AnyWalletUTXO& output : outputs) {
            // Skip outputs we cannot spend
            if (!output.IsSpendable()) continue;

            size_t ancestors, descendants;
            wallet.chain().getTransactionAncestry(output.GetTxHash(), ancestors, descendants);

            // Make an OutputGroup containing just this output
            OutputGroup group{coin_sel_params};
            group.Insert(output, ancestors, descendants, positive_only);

            // Check the OutputGroup's eligibility. Only add the eligible ones.
            if (positive_only && group.GetSelectionAmount() <= 0) continue;
            if (group.m_outputs.size() > 0 && group.EligibleForSpending(filter, coin_sel_params.m_tx_type)) groups_out.push_back(group);
        }
        return groups_out;
    }

    // We want to combine COutputs that have the same scriptPubKey into single OutputGroups
    // except when there are more than OUTPUT_GROUP_MAX_ENTRIES COutputs grouped in an OutputGroup.
    // To do this, we maintain a map where the key is the scriptPubKey and the value is a vector of OutputGroups.
    // For each CWalletUTXO, we check if the scriptPubKey is in the map, and if it is, the CWalletUTXO is added
    // to the last OutputGroup in the vector for the scriptPubKey. When the last OutputGroup has
    // OUTPUT_GROUP_MAX_ENTRIES COutputs, a new OutputGroup is added to the end of the vector.
    std::map<CTxDestination, std::vector<OutputGroup>> dest_to_groups_map;
    for (const auto& output : outputs) {
        // Skip outputs we cannot spend
        if (!output.IsSpendable()) continue;

        // MWEB: To support MWEB, we group by destination instead of CScript
        CTxDestination dest;
        if (!output.GetDestination(dest)) continue;

        size_t ancestors, descendants;
        wallet.chain().getTransactionAncestry(output.GetTxHash(), ancestors, descendants);

        std::vector<OutputGroup>& groups = dest_to_groups_map[dest];

        // MWEB outputs must be ungrouped.
        if (groups.size() == 0 || output.IsMWEB()) {
            // No OutputGroups for this scriptPubKey yet, add one
            groups.emplace_back(coin_sel_params);
        }

        // Get the last OutputGroup in the vector so that we can add the CWalletUTXO to it
        // A pointer is used here so that group can be reassigned later if it is full.
        OutputGroup* group = &groups.back();

        // Check if this OutputGroup is full. We limit to OUTPUT_GROUP_MAX_ENTRIES when using -avoidpartialspends
        // to avoid surprising users with very high fees.
        if (group->m_outputs.size() >= OUTPUT_GROUP_MAX_ENTRIES) {
            // The last output group is full, add a new group to the vector and use that group for the insertion
            groups.emplace_back(coin_sel_params);
            group = &groups.back();
        }

        // Add the output to group
        group->Insert(output, ancestors, descendants, positive_only);
    }

    // Now we go through the entire map and pull out the OutputGroups
    for (const auto& dest_and_groups_pair: dest_to_groups_map) {
        const std::vector<OutputGroup>& groups_per_dest = dest_and_groups_pair.second;

        // Go through the vector backwards. This allows for the first item we deal with being the partial group.
        for (auto group_it = groups_per_dest.rbegin(); group_it != groups_per_dest.rend(); group_it++) {
            const OutputGroup& group = *group_it;

            // Don't include partial groups if there are full groups too and we don't want partial groups
            if (group_it == groups_per_dest.rbegin() && groups_per_dest.size() > 1 && !filter.m_include_partial_groups && !group.IsMWEB()) {
                continue;
            }

            // Check the OutputGroup's eligibility. Only add the eligible ones.
            if (positive_only && group.GetSelectionAmount() <= 0) continue;
            if (group.m_outputs.size() > 0 && group.EligibleForSpending(filter, coin_sel_params.m_tx_type)) groups_out.push_back(group);
        }
    }

    return groups_out;
}

std::optional<SelectionResult> AttemptSelection(const CWallet& wallet, const CAmount& nTargetValue, const CoinEligibilityFilter& eligibility_filter, const CoinsResult& available_coins,
                               const CoinSelectionParams& coin_selection_params, bool allow_mixed_output_types)
{
    // Run coin selection on each OutputType and compute the Waste Metric
    std::vector<SelectionResult> results;
    for (const auto& it : available_coins.coins) {
        if (auto result{ChooseSelectionResult(wallet, nTargetValue, eligibility_filter, it.second, coin_selection_params)}) {
            results.push_back(*result);
        }
    }
    // If we have at least one solution for funding the transaction without mixing, choose the minimum one according to waste metric
    // and return the result
    if (results.size() > 0) return *std::min_element(results.begin(), results.end());

    // If we can't fund the transaction from any individual OutputType, run coin selection one last time
    // over all available coins, which would allow mixing
    if (allow_mixed_output_types) {
        if (auto result{ChooseSelectionResult(wallet, nTargetValue, eligibility_filter, available_coins.All(), coin_selection_params)}) {
            return result;
        }
    }
    // Either mixing is not allowed and we couldn't find a solution from any single OutputType, or mixing was allowed and we still couldn't
    // find a solution using all available coins
    return std::nullopt;
};

std::optional<SelectionResult> ChooseSelectionResult(const CWallet& wallet, const CAmount& nTargetValue, const CoinEligibilityFilter& eligibility_filter, const std::vector<AnyWalletUTXO>& available_coins, const CoinSelectionParams& coin_selection_params)
{
    // Vector of results. We will choose the best one based on waste.
    std::vector<SelectionResult> results;

    std::vector<OutputGroup> positive_groups = GroupOutputs(wallet, available_coins, coin_selection_params, eligibility_filter, /*positive_only=*/true);
    if (auto bnb_result{SelectCoinsBnB(positive_groups, nTargetValue, coin_selection_params.m_change_params.m_cost_of_change)}) {
        results.push_back(*bnb_result);
    }

    // The knapsack solver has some legacy behavior where it will spend dust outputs. We retain this behavior, so don't filter for positive only here.
    std::vector<OutputGroup> all_groups = GroupOutputs(wallet, available_coins, coin_selection_params, eligibility_filter, /*positive_only=*/false);
    if (auto knapsack_result{KnapsackSolver(all_groups, nTargetValue, coin_selection_params.m_change_params.m_min_change_target, coin_selection_params.rng_fast)}) {
        knapsack_result->ComputeAndSetWaste(coin_selection_params.m_change_params.min_viable_change, coin_selection_params.m_change_params.m_cost_of_change, coin_selection_params.m_change_params.m_change_fee);
        results.push_back(*knapsack_result);
    }

    if (auto srd_result{SelectCoinsSRD(positive_groups, nTargetValue, coin_selection_params.rng_fast)}) {
        srd_result->ComputeAndSetWaste(coin_selection_params.m_change_params.min_viable_change, coin_selection_params.m_change_params.m_cost_of_change, coin_selection_params.m_change_params.m_change_fee);
        results.push_back(*srd_result);
    }

    if (results.size() == 0) {
        // No solution found
        return std::nullopt;
    }

    // Choose the result with the least waste
    // If the waste is the same, choose the one which spends more inputs.
    auto& best_result = *std::min_element(results.begin(), results.end());
    return best_result;
}

std::optional<SelectionResult> SelectCoins(const CWallet& wallet, CoinsResult& available_coins, const CAmount& nTargetValue, const CCoinControl& coin_control, const CoinSelectionParams& coin_selection_params)
{
    CAmount value_to_select = nTargetValue;

    OutputGroup preset_inputs(coin_selection_params);

    // calculate value from preset inputs and store them
    std::set<AnyOutputID> preset_coins;

    std::vector<AnyOutputID> vPresetInputs;
    coin_control.ListSelected(vPresetInputs);
    for (const AnyOutputID& output_id : vPresetInputs) {
        if (output_id.IsMWEB()) {
            if (coin_selection_params.m_tx_type == TxType::LTC_TO_LTC) {
                return std::nullopt;
            }

            const AnyWalletUTXO* coin = available_coins.Find(output_id);
            if (coin == nullptr) {
                return std::nullopt;
            }

            mw::WalletCoin mweb_coin;
            const mw::Hash mweb_output_id = output_id.ToMWEB();
            if (IsFrozenMWEBOutput(mweb_output_id) || !wallet.GetMWEBWalletCoin(mweb_output_id, mweb_coin) || !mweb_coin.IsMine()) {
                return std::nullopt;
            }

            value_to_select -= coin->GetValue();

            preset_coins.insert(output_id);
            preset_inputs.Insert(*coin, /*ancestors=*/ 0, /*descendants=*/ 0, /*positive_only=*/ false);
            continue;
        }

        if (coin_selection_params.m_tx_type == TxType::MWEB_TO_MWEB ||
            coin_selection_params.m_tx_type == TxType::PEGOUT) {
            return std::nullopt;
        }

        const COutPoint& outpoint = output_id.ToOutPoint();
        int input_bytes = -1;
        CTxOut txout;
        auto ptr_wtx = wallet.GetWalletTx(outpoint.hash);
        if (ptr_wtx) {
            // Clearly invalid input, fail
            if (ptr_wtx->tx->vout.size() <= outpoint.n) {
                return std::nullopt;
            }
            txout = ptr_wtx->tx->vout.at(outpoint.n);
            input_bytes = CalculateMaximumSignedInputSize(txout, &wallet, &coin_control);
        } else {
            // The input is external. We did not find the tx in mapWallet.
            AnyOutput output;
            if (!coin_control.GetExternalOutput(outpoint, output)) {
                return std::nullopt;
            }

            txout = output.GetTxOut();
        }

        if (input_bytes == -1) {
            input_bytes = CalculateMaximumSignedInputSize(txout, outpoint, &coin_control.m_external_provider, &coin_control);
        }

        // If available, override calculated size with coin control specified size
        if (coin_control.HasInputWeight(outpoint)) {
            input_bytes = GetVirtualTransactionSize(coin_control.GetInputWeight(outpoint), 0, 0);
        }

        if (input_bytes == -1) {
            return std::nullopt; // Not solvable, can't estimate size for fee
        }

        /* Set some defaults for depth, spendable, solvable, safe, time, and from_me as these don't matter for preset inputs since no selection is being done. */
        CWalletUTXO output(outpoint, txout, /*depth=*/ 0, input_bytes, /*spendable=*/ true, /*solvable=*/ true, /*safe=*/ true, /*time=*/ 0, /*from_me=*/ false, coin_selection_params.m_effective_feerate);
        if (coin_selection_params.m_subtract_fee_outputs) {
            value_to_select -= output.txout.nValue;
        } else {
            value_to_select -= output.GetEffectiveValue();
        }
        preset_coins.insert(outpoint);
        /* Set ancestors and descendants to 0 as they don't matter for preset inputs since no actual selection is being done.
         * positive_only is set to false because we want to include all preset inputs, even if they are dust.
         */
        preset_inputs.Insert(output, /*ancestors=*/ 0, /*descendants=*/ 0, /*positive_only=*/ false);
    }

    // coin control -> return all selected outputs (we want all selected to go into the transaction for sure)
    if (coin_control.HasSelected() && !coin_control.m_allow_other_inputs) {
        SelectionResult result(nTargetValue, SelectionAlgorithm::MANUAL);
        result.AddInput(preset_inputs);

        if (!coin_selection_params.m_subtract_fee_outputs && result.GetSelectedEffectiveValue() < nTargetValue) {
            return std::nullopt;
        } else if (result.GetSelectedValue() < nTargetValue) {
            return std::nullopt;
        }

        result.ComputeAndSetWaste(coin_selection_params.m_change_params.min_viable_change, coin_selection_params.m_change_params.m_cost_of_change, coin_selection_params.m_change_params.m_change_fee);
        return result;
    }

    // remove preset inputs from coins so that Coin Selection doesn't pick them.
    if (coin_control.HasSelected()) {
        available_coins.Erase(preset_coins);
    }

    unsigned int limit_ancestor_count = 0;
    unsigned int limit_descendant_count = 0;
    wallet.chain().getPackageLimits(limit_ancestor_count, limit_descendant_count);
    const size_t max_ancestors = (size_t)std::max<int64_t>(1, limit_ancestor_count);
    const size_t max_descendants = (size_t)std::max<int64_t>(1, limit_descendant_count);
    const bool fRejectLongChains = gArgs.GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS);

    // form groups from remaining coins; note that preset coins will not
    // automatically have their associated (same address) coins included
    if (coin_control.m_avoid_partial_spends && available_coins.Size() > OUTPUT_GROUP_MAX_ENTRIES) {
        // Cases where we have 101+ outputs all pointing to the same destination may result in
        // privacy leaks as they will potentially be deterministically sorted. We solve that by
        // explicitly shuffling the outputs before processing
        available_coins.Shuffle(coin_selection_params.rng_fast);
    }

    SelectionResult preselected(preset_inputs.GetSelectionAmount(), SelectionAlgorithm::MANUAL);
    preselected.AddInput(preset_inputs);

    // Coin Selection attempts to select inputs from a pool of eligible UTXOs to fund the
    // transaction at a target feerate. If an attempt fails, more attempts may be made using a more
    // permissive CoinEligibilityFilter.
    std::optional<SelectionResult> res = [&] {
        // Pre-selected inputs already cover the target amount.
        if (value_to_select <= 0) return std::make_optional(SelectionResult(value_to_select, SelectionAlgorithm::MANUAL));

        // If possible, fund the transaction with confirmed UTXOs only. Prefer at least six
        // confirmations on outputs received from other wallets and only spend confirmed change.
        if (auto r1{AttemptSelection(wallet, value_to_select, CoinEligibilityFilter(1, 6, 0), available_coins, coin_selection_params, /*allow_mixed_output_types=*/false)}) return r1;
        // Allow mixing only if no solution from any single output type can be found
        if (auto r2{AttemptSelection(wallet, value_to_select, CoinEligibilityFilter(1, 1, 0), available_coins, coin_selection_params, /*allow_mixed_output_types=*/true)}) return r2;

        // Fall back to using zero confirmation change (but with as few ancestors in the mempool as
        // possible) if we cannot fund the transaction otherwise.
        if (wallet.m_spend_zero_conf_change) {
            if (auto r3{AttemptSelection(wallet, value_to_select, CoinEligibilityFilter(0, 1, 2), available_coins, coin_selection_params, /*allow_mixed_output_types=*/true)}) return r3;
            if (auto r4{AttemptSelection(wallet, value_to_select, CoinEligibilityFilter(0, 1, std::min((size_t)4, max_ancestors/3), std::min((size_t)4, max_descendants/3)),
                                   available_coins, coin_selection_params, /*allow_mixed_output_types=*/true)}) {
                return r4;
            }
            if (auto r5{AttemptSelection(wallet, value_to_select, CoinEligibilityFilter(0, 1, max_ancestors/2, max_descendants/2),
                                   available_coins, coin_selection_params, /*allow_mixed_output_types=*/true)}) {
                return r5;
            }
            // If partial groups are allowed, relax the requirement of spending OutputGroups (groups
            // of UTXOs sent to the same address, which are obviously controlled by a single wallet)
            // in their entirety.
            if (auto r6{AttemptSelection(wallet, value_to_select, CoinEligibilityFilter(0, 1, max_ancestors-1, max_descendants-1, true /* include_partial_groups */),
                                   available_coins, coin_selection_params, /*allow_mixed_output_types=*/true)}) {
                return r6;
            }
            // Try with unsafe inputs if they are allowed. This may spend unconfirmed outputs
            // received from other wallets.
            if (coin_control.m_include_unsafe_inputs) {
                if (auto r7{AttemptSelection(wallet, value_to_select,
                    CoinEligibilityFilter(0 /* conf_mine */, 0 /* conf_theirs */, max_ancestors-1, max_descendants-1, true /* include_partial_groups */),
                    available_coins, coin_selection_params, /*allow_mixed_output_types=*/true)}) {
                    return r7;
                }
            }
            // Try with unlimited ancestors/descendants. The transaction will still need to meet
            // mempool ancestor/descendant policy to be accepted to mempool and broadcasted, but
            // OutputGroups use heuristics that may overestimate ancestor/descendant counts.
            if (!fRejectLongChains) {
                if (auto r8{AttemptSelection(wallet, value_to_select,
                                      CoinEligibilityFilter(0, 1, std::numeric_limits<uint64_t>::max(), std::numeric_limits<uint64_t>::max(), true /* include_partial_groups */),
                                      available_coins, coin_selection_params, /*allow_mixed_output_types=*/true)}) {
                    return r8;
                }
            }
        }
        // Coin Selection failed.
        return std::optional<SelectionResult>();
    }();

    if (!res) return std::nullopt;

    // Add preset inputs to result
    res->Merge(preselected);
    if (res->GetAlgo() == SelectionAlgorithm::MANUAL) {
        res->ComputeAndSetWaste(coin_selection_params.m_change_params.min_viable_change, coin_selection_params.m_change_params.m_cost_of_change, coin_selection_params.m_change_params.m_change_fee);
    }

    return res;
}

static bool IsCurrentForAntiFeeSniping(interfaces::Chain& chain, const uint256& block_hash)
{
    if (chain.isInitialBlockDownload()) {
        return false;
    }
    constexpr int64_t MAX_ANTI_FEE_SNIPING_TIP_AGE = 8 * 60 * 60; // in seconds
    int64_t block_time;
    CHECK_NONFATAL(chain.findBlock(block_hash, FoundBlock().time(block_time)));
    if (block_time < (GetTime() - MAX_ANTI_FEE_SNIPING_TIP_AGE)) {
        return false;
    }
    return true;
}

/**
 * Set a height-based locktime for new transactions (uses the height of the
 * current chain tip unless we are not synced with the current chain
 */
void DiscourageFeeSniping(CMutableTransaction& tx, FastRandomContext& rng_fast,
                                 interfaces::Chain& chain, const uint256& block_hash, int block_height)
{
    // All inputs must be added by now
    assert(!CTransaction(tx).GetInputs().empty());
    // Discourage fee sniping.
    //
    // For a large miner the value of the transactions in the best block and
    // the mempool can exceed the cost of deliberately attempting to mine two
    // blocks to orphan the current best block. By setting nLockTime such that
    // only the next block can include the transaction, we discourage this
    // practice as the height restricted and limited blocksize gives miners
    // considering fee sniping fewer options for pulling off this attack.
    //
    // A simple way to think about this is from the wallet's point of view we
    // always want the blockchain to move forward. By setting nLockTime this
    // way we're basically making the statement that we only want this
    // transaction to appear in the next block; we don't want to potentially
    // encourage reorgs by allowing transactions to appear at lower heights
    // than the next block in forks of the best chain.
    //
    // Of course, the subsidy is high enough, and transaction volume low
    // enough, that fee sniping isn't a problem yet, but by implementing a fix
    // now we ensure code won't be written that makes assumptions about
    // nLockTime that preclude a fix later.
    if (IsCurrentForAntiFeeSniping(chain, block_hash)) {
        tx.nLockTime = block_height;

        // Secondly occasionally randomly pick a nLockTime even further back, so
        // that transactions that are delayed after signing for whatever reason,
        // e.g. high-latency mix networks and some CoinJoin implementations, have
        // better privacy.
        if (rng_fast.randrange(10) == 0) {
            tx.nLockTime = std::max(0, int(tx.nLockTime) - int(rng_fast.randrange(100)));
        }
    } else {
        // If our chain is lagging behind, we can't discourage fee sniping nor help
        // the privacy of high-latency transactions. To avoid leaking a potentially
        // unique "nLockTime fingerprint", set nLockTime to a constant.
        tx.nLockTime = 0;
    }
    // Sanity check all values
    assert(tx.nLockTime < LOCKTIME_THRESHOLD); // Type must be block height
    assert(tx.nLockTime <= uint64_t(block_height));
    for (const auto& in : tx.vin) {
        // Can not be FINAL for locktime to work
        assert(in.nSequence != CTxIn::SEQUENCE_FINAL);
        // May be MAX NONFINAL to disable both BIP68 and BIP125
        if (in.nSequence == CTxIn::MAX_SEQUENCE_NONFINAL) continue;
        // May be MAX BIP125 to disable BIP68 and enable BIP125
        if (in.nSequence == MAX_BIP125_RBF_SEQUENCE) continue;
        // The wallet does not support any other sequence-use right now.
        assert(false);
    }
}

util::Result<CreatedTransactionResult> CreateTransaction(
        CWallet& wallet,
        const std::vector<CRecipient>& vecSend,
        int change_pos,
        const CCoinControl& coin_control,
        const std::optional<int32_t>& nVersion,
        const std::optional<uint32_t>& nLockTime,
        bool sign)
{
    if (vecSend.empty()) {
        return util::Error{_("Transaction must have at least one recipient")};
    }

    if (std::any_of(vecSend.cbegin(), vecSend.cend(), [](const auto& recipient){ return recipient.nAmount < 0; })) {
        return util::Error{_("Transaction amounts must not be negative")};
    }

    if (vecSend.size() > 1) {
        if (std::any_of(vecSend.cbegin(), vecSend.cend(), [](const auto& recipient){ return recipient.IsMWEB(); })) {
            return util::Error{_("Only one MWEB recipient supported")};
        }
    }

    if (std::holds_alternative<StealthAddress>(coin_control.destChange)) {
        return util::Error{_("Custom MWEB change addresses not yet supported")};
    }

    for (const CRecipient& recipient : vecSend) {
        if (!recipient.IsMWEB()) {
            CTxOut txout(recipient.nAmount, recipient.GetScript());
            if (IsDust(txout, wallet.chain().relayDustFee())) {
                return util::Error{_("Transaction amount too small")};
            }
        }
    }

    LOCK(wallet.cs_wallet);

    const std::optional<int> opt_change_pos = (change_pos != -1) ? std::make_optional<int>(change_pos) : std::nullopt;
    auto res = TxBuilder::New(wallet, coin_control, vecSend, opt_change_pos)->Build(nVersion, nLockTime, sign);
    TRACE4(coin_selection, normal_create_tx_internal, wallet.GetName().c_str(), bool(res),
           res ? res->fee : 0, res ? res->change_pos : 0);
    if (!res) return res;
    const auto& txr_ungrouped = *res;
    // try with avoidpartialspends unless it's enabled already
    if (txr_ungrouped.fee > 0 /* 0 means non-functional fee rate estimation */ && wallet.m_max_aps_fee > -1 && !coin_control.m_avoid_partial_spends) {
        TRACE1(coin_selection, attempting_aps_create_tx, wallet.GetName().c_str());
        CCoinControl tmp_cc = coin_control;
        tmp_cc.m_avoid_partial_spends = true;
        auto txr_grouped = TxBuilder::New(wallet, tmp_cc, vecSend, opt_change_pos)->Build(nVersion, nLockTime, sign);
        // if fee of this alternative one is within the range of the max fee, we use this one
        const bool use_aps{txr_grouped.has_value() ? (txr_grouped->fee <= txr_ungrouped.fee + wallet.m_max_aps_fee) : false};
        TRACE5(coin_selection, aps_create_tx_internal, wallet.GetName().c_str(), use_aps, txr_grouped.has_value(),
               txr_grouped.has_value() ? txr_grouped->fee : 0, txr_grouped.has_value() ? txr_grouped->change_pos : 0);
        if (txr_grouped) {
            wallet.WalletLogPrintf("Fee non-grouped = %lld, grouped = %lld, using %s\n",
                txr_ungrouped.fee, txr_grouped->fee, use_aps ? "grouped" : "non-grouped");
            if (use_aps) return txr_grouped;
        }
    }
    return res;
}
} // namespace wallet
