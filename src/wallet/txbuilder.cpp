#include <wallet/txbuilder.h>

#include <consensus/validation.h>
#include <mw/wallet/sign.h>
#include <mweb/mweb_wallet.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <script/standard.h>
#include <util/check.h>
#include <util/fees.h>
#include <util/moneystr.h>
#include <util/rbf.h>
#include <util/trace.h>
#include <wallet/change.h>
#include <wallet/fees.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <map>

namespace wallet {

namespace {

std::optional<size_t> FindSortedMWEBOutputIndex(const std::vector<mw::MutableOutput>& outputs, const mw::Hash& output_id)
{
    std::vector<mw::Hash> output_ids;
    output_ids.reserve(outputs.size());

    for (const mw::MutableOutput& output : outputs) {
        const std::optional<mw::Hash> id = output.CalcOutputID();
        if (!id.has_value()) {
            return std::nullopt;
        }

        output_ids.push_back(*id);
    }

    std::sort(output_ids.begin(), output_ids.end());
    auto output_iter = std::find(output_ids.cbegin(), output_ids.cend(), output_id);
    if (output_iter == output_ids.cend()) {
        return std::nullopt;
    }

    return static_cast<size_t>(std::distance(output_ids.cbegin(), output_iter));
}

std::map<mw::Hash, StealthAddress> GetMWEBOutputAddresses(const mw::MutableTx& tx)
{
    std::map<mw::Hash, StealthAddress> addresses;
    for (const mw::MutableOutput& output : tx.outputs) {
        if (!output.address.has_value()) {
            continue;
        }

        const std::optional<mw::Hash> output_id = output.CalcOutputID();
        if (output_id.has_value()) {
            addresses[*output_id] = *output.address;
        }
    }
    return addresses;
}

struct SelectedInputTypes {
    bool ltc{false};
    bool mweb{false};
};

SelectedInputTypes GetSelectedInputTypes(const CCoinControl& coin_control)
{
    SelectedInputTypes selected;

    std::vector<AnyOutputID> selected_inputs;
    coin_control.ListSelected(selected_inputs);
    for (const AnyOutputID& input : selected_inputs) {
        if (input.IsMWEB()) {
            selected.mweb = true;
        } else {
            selected.ltc = true;
        }
    }

    return selected;
}

bool SelectionHasLTCInput(const SelectionResult& result)
{
    return std::any_of(result.GetInputSet().cbegin(), result.GetInputSet().cend(), [](const AnyWalletUTXO& coin) {
        return !coin.IsMWEB();
    });
}

bool SelectionHasMWEBInput(const SelectionResult& result)
{
    return std::any_of(result.GetInputSet().cbegin(), result.GetInputSet().cend(), [](const AnyWalletUTXO& coin) {
        return coin.IsMWEB();
    });
}

struct TransactionAmounts {
    CAmount ltc_inputs{0};
    CAmount ltc_outputs{0};
    CAmount mweb_inputs{0};
    CAmount mweb_outputs{0};
    CAmount pegin{0};
    CAmount pegouts{0};

    CAmount GetFeePaid() const
    {
        return (ltc_inputs - ltc_outputs) + (mweb_inputs + pegin - mweb_outputs - pegouts);
    }

    CAmount GetRequiredPegin(const CAmount mweb_fee) const
    {
        return mweb_outputs + pegouts + mweb_fee - mweb_inputs;
    }
};

TransactionAmounts GetTransactionAmounts(const std::vector<AnyWalletUTXO>& inputs, const CMutableTransaction& tx)
{
    TransactionAmounts amounts;
    for (const AnyWalletUTXO& input : inputs) {
        if (input.IsMWEB()) {
            amounts.mweb_inputs += input.GetValue();
        } else {
            amounts.ltc_inputs += input.GetValue();
        }
    }

    for (const CTxOut& output : tx.vout) {
        amounts.ltc_outputs += output.nValue;
    }

    for (const mw::MutableOutput& output : tx.mweb_tx.outputs) {
        amounts.mweb_outputs += output.amount.value_or(0);
    }

    amounts.pegin = tx.mweb_tx.GetPeginAmount().value_or(0);
    amounts.pegouts = tx.mweb_tx.GetTotalPegoutAmount();
    return amounts;
}

} // namespace

TxBuilder::Ptr TxBuilder::New(const CWallet& wallet, const CCoinControl& coin_control, const std::vector<CRecipient>& recipients, const std::optional<int>& change_position)
{
    ChangeBuilder change = ChangeBuilder::New(wallet, coin_control, recipients, change_position);

    return TxBuilder::Ptr(new TxBuilder{wallet, coin_control, recipients, std::move(change)});
}

util::Result<CreatedTransactionResult> TxBuilder::Build(const std::optional<int32_t>& nVersion, const std::optional<uint32_t>& nLockTime, bool sign)
{

    m_tx.nVersion = nVersion.value_or(CTransaction::CURRENT_VERSION);
    m_tx.nLockTime = nLockTime.value_or(0);

    m_selection_params.m_avoid_partial_spends = m_coin_control.m_avoid_partial_spends;
    m_selection_params.m_long_term_feerate = m_wallet.m_consolidate_feerate;
    m_selection_params.m_subtract_fee_outputs = m_recipients.NumOutputsToSubtractFeeFrom() > 0;

    FeeCalculation feeCalc;
    m_selection_params.m_effective_feerate = GetMinimumFeeRate(m_wallet, m_coin_control, &feeCalc);
    m_selection_params.m_discard_feerate = GetDiscardRate(m_wallet);

    // Do not, ever, assume that it's fine to change the fee rate if the user has explicitly provided one
    if (m_coin_control.m_feerate && m_selection_params.m_effective_feerate > *m_coin_control.m_feerate) {
        return util::Error{strprintf(_("Fee rate (%s) is lower than the minimum fee rate setting (%s)"), m_coin_control.m_feerate->ToString(FeeEstimateMode::SAT_VB), m_selection_params.m_effective_feerate.ToString(FeeEstimateMode::SAT_VB))};
    }

    if (feeCalc.reason == FeeReason::FALLBACK && !m_wallet.m_allow_fallback_fee) {
        // eventually allow a fallback fee
        return util::Error{_("Fee estimation failed. Fallbackfee is disabled. Wait a few blocks or enable -fallbackfee.")};
    }
    
    // Get available coins
    auto available_coins = AvailableCoins(
        m_wallet,
        &m_coin_control,
        GetFeeRate(),
        1,          /*nMinimumAmount*/
        MAX_MONEY,  /*nMaximumAmount*/
        MAX_MONEY,  /*nMinimumSumAmount*/
        0           /*nMaximumCount*/
    );
    
    // Select coins to spend
    auto result = SelectInputCoins(available_coins);
    if (!result) {
        return util::Error{ErrorString(result)};
    }
    
    std::vector<AnyWalletUTXO> selected_coins = result->GetShuffledInputVector();
    TRACE5(coin_selection, selected_coins, m_wallet.GetName().c_str(), GetAlgorithmName(result->GetAlgo()).c_str(), result->GetTarget(), result->GetWaste(), result->GetSelectedValue());

    // Add selected inputs
    AddInputs(selected_coins);

    // Use a height-based locktime to discourage fee sniping. Skip this for MWEB_TO_MWEB and PEGOUT transactions, since they don't have a LTC transaction.
    if (!nLockTime.has_value() && !m_tx.vin.empty()) {
        DiscourageFeeSniping(m_tx, m_selection_params.rng_fast, m_wallet.chain(), m_wallet.GetLastBlockHash(), m_wallet.GetLastBlockHeight());
    }
    
    // Add outputs (recipients, change, pegin)
    auto add_outputs_error = AddOutputs(*result);
    if (add_outputs_error.has_value()) {
        return add_outputs_error.value();
    }

    // Update MWEB fee
    if (GetTxType() != TxType::LTC_TO_LTC) {
        m_tx.mweb_tx.SetFee(CalcMWEBFee());
    }

    // Give up if change keypool ran out and change is required
    if (m_change.script_or_address.IsEmpty() && !m_change.change_position.IsNull()) {
        return util::Error{m_change.error};
    }

    // Sign the transaction
    if (sign) {
        auto add_mweb_tx_error = SignMWEBTx();
        if (add_mweb_tx_error.has_value()) {
            return add_mweb_tx_error.value();
        }

        // SignMWEBTx may rewrite peg-in scriptPubKeys with finalized kernel IDs.
        // Any PrecomputedTransactionData for m_tx must be built after this point.
        if (!m_wallet.SignTransaction(m_tx)) {
            return util::Error{_("Signing transaction failed")};
        }
    }

    // Return the constructed transaction data.
    CTransactionRef tx = MakeTransactionRef(CTransaction(m_tx));

    int64_t weight = 0;
    if (sign) {
        weight = GetTransactionWeight(*tx);
    } else {
        auto tx_size = CalcMaxSignedTxSize(m_tx);
        if (!tx_size) {
            return util::Error{ErrorString(tx_size)};
        }
        weight = tx_size->weight;
    }

    // Limit size
    if (weight > MAX_STANDARD_TX_WEIGHT) {
        return util::Error{_("Transaction too large")};
    }

    const CAmount fee_paid = GetFeePaid();
    if (fee_paid > m_wallet.m_default_max_tx_fee) {
        return util::Error{TransactionErrorString(TransactionError::MAX_FEE_EXCEEDED)};
    }

    if (gArgs.GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS)) {
        // Lastly, ensure this tx will pass the mempool's chain limits
        if (!m_wallet.chain().checkChainLimits(tx)) {
            return util::Error{_("Transaction has too long of a mempool chain")};
        }
    }

    // Before we return success, we assume any change key will be used to prevent
    // accidental re-use.
    if (m_change.reserve_dest) {
        m_change.reserve_dest->KeepDestination();
    }
    
    m_wallet.WalletLogPrintf("Fee Calculation: Fee:%d Weight:%d Tgt:%d (requested %d) Reason:\"%s\" Decay %.5f: Estimation: (%g - %g) %.2f%% %.1f/(%.1f %d mem %.1f out) Fail: (%g - %g) %.2f%% %.1f/(%.1f %d mem %.1f out)\n",
              fee_paid, weight, feeCalc.returnedTarget, feeCalc.desiredTarget, StringForFeeReason(feeCalc.reason), feeCalc.est.decay,
              feeCalc.est.pass.start, feeCalc.est.pass.end,
              (feeCalc.est.pass.totalConfirmed + feeCalc.est.pass.inMempool + feeCalc.est.pass.leftMempool) > 0.0 ? 100 * feeCalc.est.pass.withinTarget / (feeCalc.est.pass.totalConfirmed + feeCalc.est.pass.inMempool + feeCalc.est.pass.leftMempool) : 0.0,
              feeCalc.est.pass.withinTarget, feeCalc.est.pass.totalConfirmed, feeCalc.est.pass.inMempool, feeCalc.est.pass.leftMempool,
              feeCalc.est.fail.start, feeCalc.est.fail.end,
              (feeCalc.est.fail.totalConfirmed + feeCalc.est.fail.inMempool + feeCalc.est.fail.leftMempool) > 0.0 ? 100 * feeCalc.est.fail.withinTarget / (feeCalc.est.fail.totalConfirmed + feeCalc.est.fail.inMempool + feeCalc.est.fail.leftMempool) : 0.0,
              feeCalc.est.fail.withinTarget, feeCalc.est.fail.totalConfirmed, feeCalc.est.fail.inMempool, feeCalc.est.fail.leftMempool);
    return CreatedTransactionResult(m_tx, fee_paid, m_change.GetPosition(), feeCalc);
}

util::Result<SelectionResult> TxBuilder::SelectInputCoins(const CoinsResult& available_coins)
{
    const SelectedInputTypes selected_inputs = GetSelectedInputTypes(m_coin_control);
    const bool has_mweb_recipient = !m_recipients.MWEB().empty();
    const bool change_is_set = !std::holds_alternative<CNoDestination>(m_coin_control.destChange);
    const bool change_is_mweb = std::holds_alternative<StealthAddress>(m_coin_control.destChange);
    const bool explicit_ltc_change = change_is_set && !change_is_mweb;

    auto selected_inputs_compatible = [&](const TxType& tx_type) {
        switch (tx_type) {
        case TxType::LTC_TO_LTC:
            return !selected_inputs.mweb;
        case TxType::MWEB_TO_MWEB:
        case TxType::PEGOUT:
            return !selected_inputs.ltc;
        case TxType::PEGIN:
        case TxType::PEGIN_PEGOUT:
            return true;
        }

        assert(false);
        return false;
    };

    auto selection_result_matches_type = [](const TxType& tx_type, const SelectionResult& result) {
        switch (tx_type) {
        case TxType::LTC_TO_LTC:
            return !SelectionHasMWEBInput(result);
        case TxType::MWEB_TO_MWEB:
        case TxType::PEGOUT:
            return !SelectionHasLTCInput(result);
        case TxType::PEGIN:
            return SelectionHasLTCInput(result);
        case TxType::PEGIN_PEGOUT:
            return SelectionHasLTCInput(result);
        }

        assert(false);
        return false;
    };

    auto select_by_type = [&](const TxType& tx_type) -> std::optional<SelectionResult> {
        LOCK(m_wallet.cs_wallet);
        if (!selected_inputs_compatible(tx_type)) return {};

        m_selection_params.m_tx_type = tx_type;

        auto change_params = m_change.BuildParams(m_wallet, m_coin_control, m_selection_params, m_recipients);
        if (!change_params) return {};
        m_selection_params.m_change_params = *change_params;

        const CAmount nTarget = CalcSelectionTarget(tx_type);
        CoinsResult available_coins_mut = available_coins;

        std::optional<SelectionResult> result = SelectCoins(m_wallet, available_coins_mut, nTarget, m_coin_control, m_selection_params);
        if (result.has_value() && !selection_result_matches_type(tx_type, *result)) {
            return {};
        }

        return result;
    };
    
    if (has_mweb_recipient) {
        if (explicit_ltc_change) {
            std::optional<SelectionResult> pegout_result = select_by_type(TxType::PEGOUT);
            if (pegout_result.has_value()) {
                return *pegout_result;
            }

            std::optional<SelectionResult> pegin_pegout_result = select_by_type(TxType::PEGIN_PEGOUT);
            if (pegin_pegout_result.has_value()) {
                return *pegin_pegout_result;
            }
        } else {
            // First try to construct an MWEB-to-MWEB transaction
            std::optional<SelectionResult> mweb_to_mweb_result = select_by_type(TxType::MWEB_TO_MWEB);
            if (mweb_to_mweb_result.has_value()) {
                return *mweb_to_mweb_result;
            }

            // If MWEB-to-MWEB fails, create a peg-in transaction
            std::optional<SelectionResult> pegin_result = select_by_type(TxType::PEGIN);
            if (pegin_result.has_value()) {
                return *pegin_result;
            }
        }
    } else {
        // First try to construct a LTC-to-LTC transaction
        std::optional<SelectionResult> ltc_to_ltc_result = select_by_type(TxType::LTC_TO_LTC);
        if (ltc_to_ltc_result.has_value()) {
            return *ltc_to_ltc_result;
        }

        // If LTC-to-LTC fails, try a simple peg-out transaction (MWEB->LTC)
        std::optional<SelectionResult> mweb_to_ltc_result = select_by_type(TxType::PEGOUT);
        if (mweb_to_ltc_result.has_value()) {
            return *mweb_to_ltc_result;
        }

        // If simple peg-out fails, try a complex peg-out transaction (LTC->MWEB->LTC)
        std::optional<SelectionResult> pegin_pegout_result =  select_by_type(TxType::PEGIN_PEGOUT);
        if (pegin_pegout_result.has_value()) {
            return *pegin_pegout_result;
        }
    }

    return util::Error{_("Insufficient funds")};
}

void TxBuilder::AddInputs(const std::vector<AnyWalletUTXO>& shuffled_inputs)
{
    m_selected_coins = shuffled_inputs;

    // The sequence number is set to non-maxint so that DiscourageFeeSniping
    // works.
    //
    // BIP125 defines opt-in RBF as any nSequence < maxint-1, so
    // we use the highest possible value in that range (maxint-2)
    // to avoid conflicting with other possible uses of nSequence,
    // and in the spirit of "smallest possible change from prior
    // behavior."
    const uint32_t nSequence{m_coin_control.m_signal_bip125_rbf.value_or(m_wallet.m_signal_rbf) ? MAX_BIP125_RBF_SEQUENCE : CTxIn::MAX_SEQUENCE_NONFINAL};
    for (const AnyWalletUTXO& utxo : shuffled_inputs) {
        if (utxo.IsMWEB()) {
            m_tx.mweb_tx.inputs.push_back(mw::MutableInput::FromWalletCoin(utxo.GetMWEB().coin));
        } else {
            m_tx.vin.push_back(CTxIn(utxo.GetID().ToOutPoint(), CScript(), nSequence));
        }
    }
}

std::optional<util::Error> TxBuilder::AddOutputs(const SelectionResult& selection_result)
{

    const TxType tx_type = GetTxType();

    // Outputs for the payees
    for (const CRecipient& recipient : m_recipients.All()) {
        if (recipient.IsMWEB()) {
            mw::MutableOutput mweb_output;
            mweb_output.amount = recipient.nAmount;
            mweb_output.address = recipient.GetMWEBAddress();
            mweb_output.subtract_fee_from_amount = recipient.fSubtractFeeFromAmount;
            m_tx.mweb_tx.outputs.push_back(std::move(mweb_output));
        } else {
            if (tx_type == TxType::PEGOUT || tx_type == TxType::PEGIN_PEGOUT) {
                m_tx.mweb_tx.AddPegout(recipient.GetScript(), recipient.nAmount, recipient.fSubtractFeeFromAmount);
            } else {
                m_tx.vout.push_back(CTxOut(recipient.nAmount, recipient.GetScript()));
            }
        }
    }

    // Add the change output
    const std::optional<util::Error> error = AddChangeOutput(selection_result);
    if (error.has_value()) {
        return error;
    }

    // Add peg-in output for PEGIN and PEGIN_PEGOUT transactions
    if (tx_type == TxType::PEGIN || tx_type == TxType::PEGIN_PEGOUT) {
        const std::optional<util::Error> error = AddPeginOutput();
        if (error.has_value()) {
            return error;
        }
    }

    util::Result<CAmount> ltc_fee_result = CalcLTCFee();
    if (!ltc_fee_result) {
        return util::Error{ErrorString(ltc_fee_result)};
    }

    const CAmount mweb_fee = CalcMWEBFee();
    const CAmount need_fee = *ltc_fee_result + mweb_fee;
    CAmount have_fee = GetFeePaid();

    // If there is a change output and we overpay the fees, then increase the change to match the fee needed.
    if (need_fee < have_fee && !m_change.GetPosition().IsNull()) {
        GrowChangeBy(have_fee - need_fee);
        have_fee = need_fee;
    }

    // If we’re under-paying or over-paying fees and user asked to subtract from outputs
    if (have_fee != need_fee && m_selection_params.m_subtract_fee_outputs) {
        // Note that missing_fee could be negative, in which case SubtractFeeFromOutputs will add the difference to the outputs.
        const CAmount missing_fee = need_fee - have_fee;
        auto error = SubtractFeeFromOutputs(missing_fee);
        if (error) {
            return error;
        }
        have_fee += missing_fee;

        if ((tx_type == TxType::PEGIN || tx_type == TxType::PEGIN_PEGOUT) && !m_change.change_position.IsMWEB()) {
            error = UpdatePeginOutput();
            if (error) {
                return error;
            }
            have_fee = GetFeePaid();
        }
    }

    if (have_fee < need_fee) {
        return util::Error{_("Insufficient funds")};
    }

    // A transaction with change should pay exactly the requested fee. Without
    // change, any excess selected value becomes additional fee.
    if (!m_change.GetPosition().IsNull() && have_fee != need_fee) {
        return util::Error{_("Failed to calculate transaction fee")};
    }

    return std::nullopt;
}

std::optional<util::Error> TxBuilder::AddChangeOutput(const SelectionResult& selection_result)
{
    const CAmount change_amount = selection_result.GetChange(m_selection_params.m_change_params.min_viable_change, m_selection_params.m_change_params.m_change_fee);
    if (change_amount > 0) {
        m_change.amount = change_amount;
        if (ChangeBuilder::ChangeBelongsOnMWEB(GetTxType(), m_coin_control.destChange)) {
            if (std::holds_alternative<CNoDestination>(m_coin_control.destChange)) {
                // MW: TODO - Use a reserved MWEB change address once the wallet has a
                // real MWEB internal/change keypool and can persist change
                // metadata for non-CHANGE_INDEX outputs.
                m_change.reserve_dest.reset();

                StealthAddress change_address;
                if (!m_wallet.GetMWWallet()->GetStealthAddress(mw::CHANGE_INDEX, change_address)) {
                    return util::Error{_("Failed to retrieve change stealth address")};
                }
                m_change.script_or_address = change_address;
            }

            mw::MutableOutput mweb_output;
            mweb_output.address = m_change.script_or_address.GetMWEBAddress();
            mweb_output.amount = change_amount;
            mweb_output.subtract_fee_from_amount = false;

            m_change.change_position = MWEBChangePosition{m_tx.mweb_tx.outputs.size(), std::nullopt};
            m_tx.mweb_tx.outputs.push_back(std::move(mweb_output));
        } else {
            if (ChangeBuilder::ChangeBelongsOnPegout(GetTxType(), m_coin_control.destChange)) {
                m_change.change_position = PegoutChangePosition{m_tx.mweb_tx.GetPegouts().size()};
                m_tx.mweb_tx.AddPegout(m_change.script_or_address.GetScript(), change_amount, false);
            } else {
                if (m_change.script_or_address.IsMWEB()) {
                    return util::Error{_("MWEB change is incompatible with this transaction type")};
                }

                CTxOut newTxOut(change_amount, m_change.script_or_address.GetScript());
                if (m_change.change_position.IsNull()) {
                    // Insert change txn at random position:
                    m_change.change_position = m_selection_params.rng_fast.randrange(m_tx.vout.size() + 1);
                } else if (m_change.change_position.IsLTC() && m_change.change_position.ToLTC() > m_tx.vout.size()) {
                    return util::Error{_("Transaction change output index out of range")};
                }
    
                if (m_change.change_position.IsLTC()) {
                    m_tx.vout.insert(m_tx.vout.begin() + m_change.change_position.ToLTC(), newTxOut);
                }
            }
        }
    } else {
        m_change.amount = 0;
        m_change.change_position.SetNull();
    }

    return std::nullopt;
}

std::optional<util::Error> TxBuilder::AddPeginOutput()
{
    m_tx.vout.push_back(CTxOut{0, GetScriptForPegin(mw::Hash())});

    return UpdatePeginOutput();
}

std::optional<util::Error> TxBuilder::UpdatePeginOutput()
{
    if (m_tx.vout.empty()) {
        return util::Error{_("Transaction is missing peg-in output")};
    }

    const TransactionAmounts amounts = GetTransactionAmounts(m_selected_coins, m_tx);
    CTxOut& pegin_output = m_tx.vout.back();
    CAmount pegin_amount{0};
    if (!m_change.change_position.IsMWEB() && !m_change.change_position.IsPegout()) {
        // Balance the MWEB side when there is no change output to absorb the difference.
        pegin_amount = amounts.GetRequiredPegin(CalcMWEBFee());
    } else {
        // All selected LTC value is pegged in, less the fee paid on the LTC side.
        const util::Result<CAmount> ltc_fee_result = CalcLTCFee();
        if (!ltc_fee_result) {
            return util::Error{ErrorString(ltc_fee_result)};
        }
        pegin_amount = amounts.ltc_inputs - *ltc_fee_result;
    }

    pegin_output.nValue = pegin_amount;
    m_tx.mweb_tx.SetPeginAmount(pegin_amount);

    if (pegin_amount < 0) {
        return util::Error{_("The transaction amount is too small to pay the fee")};
    } else if (IsDust(pegin_output, m_wallet.chain().relayDustFee())) {
        return util::Error{_("The transaction amount is too small to send after the fee has been deducted")};
    }

    return std::nullopt;
}

void TxBuilder::GrowChangeBy(const CAmount growth_amount)
{
    if (m_change.GetPosition().IsLTC()) {
        auto& change = m_tx.vout.at(m_change.GetPosition().ToLTC());
        change.nValue += growth_amount;
    } else if (m_change.GetPosition().IsMWEB()) {
        const size_t change_idx = m_change.GetPosition().ToMWEB().idx;
        m_change.amount += growth_amount;
        mw::MutableOutput& change_output = m_tx.mweb_tx.outputs.at(change_idx);
        *change_output.amount += growth_amount;
    } else if (m_change.GetPosition().IsPegout()) {
        const size_t change_pegout_position = m_change.GetPosition().ToPegout().idx;
        size_t pegout_idx{0};
        for (mw::MutableKernel& kernel : m_tx.mweb_tx.kernels) {
            for (mw::PegOutRecipient& pegout : kernel.pegouts) {
                if (pegout_idx == change_pegout_position) {
                    pegout.nAmount += growth_amount;
                    m_change.amount += growth_amount;
                    return;
                }
                ++pegout_idx;
            }
        }
        assert(false);
    } else {
        assert(false);
    }
}

std::optional<util::Error> TxBuilder::SubtractFeeFromOutputs(const CAmount fee_to_distribute)
{

    const size_t outputs_to_subtract_fee_from = m_recipients.NumOutputsToSubtractFeeFrom();
    bool fFirst = true;

    // Subtract fee from LTC outputs
    if (m_tx.mweb_tx.GetPegouts().empty()) {
        size_t i = 0;
        for (const auto& recipient : m_recipients.LTC()) {
            ChangePosition change_pos = m_change.GetPosition();
            if (change_pos == i) {
                i++;
            }

            CTxOut& txout = m_tx.vout[i];
            if (recipient.fSubtractFeeFromAmount) {
                txout.nValue -= fee_to_distribute / outputs_to_subtract_fee_from; // Subtract fee equally from each selected recipient

                // first receiver pays the remainder not divisible by output count
                if (fFirst) {
                    fFirst = false;
                    txout.nValue -= fee_to_distribute % outputs_to_subtract_fee_from;
                }
            }

            // Error if this output is reduced to be below dust
            if (txout.nValue < 0) {
                return util::Error{_("The transaction amount is too small to pay the fee")};
            } else if (IsDust(txout, m_wallet.chain().relayDustFee())) {
                return util::Error{_("The transaction amount is too small to send after the fee has been deducted")};
            }

            i++;
        }
    }

    // Subtract fee from MWEB outputs
    for (mw::MutableOutput& output : m_tx.mweb_tx.outputs) {
        if (!output.amount.has_value()) {
            return util::Error{_("Transaction has an invalid MWEB output amount")};
        }

        if (output.subtract_fee_from_amount.value_or(false)) {
            *output.amount -= fee_to_distribute / outputs_to_subtract_fee_from;

            if (fFirst) {
                fFirst = false;
                *output.amount -= fee_to_distribute % outputs_to_subtract_fee_from;
            }
        }

        if (*output.amount < 0) {
            return util::Error{_("The transaction amount is too small to pay the fee")};
        }
    }

    // Subtract fee from pegouts.
    for (mw::MutableKernel& kernel : m_tx.mweb_tx.kernels) {
        for (mw::PegOutRecipient& recipient : kernel.pegouts) {
            if (recipient.fSubtractFeeFromAmount) {
                recipient.nAmount -= fee_to_distribute / outputs_to_subtract_fee_from;

                if (fFirst) {
                    fFirst = false;
                    recipient.nAmount -= fee_to_distribute % outputs_to_subtract_fee_from;
                }
            }

            if (recipient.nAmount < 0) {
                return util::Error{_("The transaction amount is too small to pay the fee")};
            } else if (IsDust(CTxOut(recipient.nAmount, recipient.script), m_wallet.chain().relayDustFee())) {
                return util::Error{_("The transaction amount is too small to send after the fee has been deducted")};
            }
        }
    }

    return std::nullopt;
}

std::optional<util::Error> TxBuilder::SignMWEBTx()
{
    if (GetTxType() == TxType::LTC_TO_LTC) {
        return std::nullopt;
    }

    if (!m_wallet.CompleteMWEBInputData(m_tx)) {
        return util::Error{_("Failed to prepare MWEB inputs for signing")};
    }

    SecretKey rewind_key = SecretKey::Random();
    mw::SenderKeyGenerator generate_sender_key = []() -> util::Result<SecretKey> {
        return SecretKey::Random();
    };
    if (m_wallet.GetMWWallet()) {
        const std::shared_ptr<MWEB::Wallet>& mweb_wallet = m_wallet.GetMWWallet();
        rewind_key = mweb_wallet->GetRewindKey().value_or(rewind_key);
        generate_sender_key = [&wallet = m_wallet, mweb_wallet]() -> util::Result<SecretKey> {
            LOCK(wallet.cs_wallet);
            return mweb_wallet->GenerateSenderKey();
        };
    }

    util::Result<mw::SignTxResult> sign_tx_result = mw::SignTx(m_tx, rewind_key, generate_sender_key);
    if (!sign_tx_result) {
        return util::Error{util::ErrorString(sign_tx_result)};
    }


    // Update change position now that finalized output IDs are known.
    if (m_change.change_position.IsMWEB()) {
        const size_t change_idx = m_change.change_position.ToMWEB().idx;
        if (change_idx >= m_tx.mweb_tx.outputs.size()) {
            return util::Error{_("Transaction change output index out of range")};
        }

        const std::optional<mw::Hash> output_id = m_tx.mweb_tx.outputs.at(change_idx).CalcOutputID();
        if (!output_id.has_value()) {
            return util::Error{_("Failed to determine MWEB change output ID")};
        }

        const std::optional<size_t> sorted_idx = FindSortedMWEBOutputIndex(m_tx.mweb_tx.outputs, *output_id);
        if (!sorted_idx.has_value()) {
            return util::Error{_("Failed to determine MWEB change output position")};
        }

        m_change.change_position = MWEBChangePosition{*sorted_idx, *output_id};
    }

    // Stage all signed coins so output amounts are available once the tx is committed.
    if (!sign_tx_result->wallet_coins_by_output_id.empty()) {
        m_wallet.GetMWWallet()->StageWalletCoins(sign_tx_result->wallet_coins_by_output_id);
    }
    m_wallet.GetMWWallet()->StageOutputAddresses(GetMWEBOutputAddresses(m_tx.mweb_tx));

    return std::nullopt;
}

CAmount TxBuilder::CalcSelectionTarget(const TxType& tx_type) const
{
    const CAmount recipients_sum = m_recipients.Sum();
    if (m_selection_params.m_subtract_fee_outputs) {
        return recipients_sum;
    }

    const std::vector<CRecipient> ltc_recipients = m_recipients.LTC();
    const std::vector<CRecipient> mweb_recipients = m_recipients.MWEB();

    // Fee rounding happens independently on the LTC and MWEB sides, so keep
    // those byte counts separate just as the final fee calculation does.
    const auto get_layered_fee = [this](size_t ltc_bytes, size_t mweb_bytes, size_t mweb_weight) {
        return GetFeeRate().GetFee(ltc_bytes, 0) + GetFeeRate().GetFee(mweb_bytes, mweb_weight);
    };

    // Static vsize overhead: version, locktime, input count, witness overhead,
    // and the compact-size encoded output count.
    const auto get_ltc_tx_overhead = [](size_t num_outputs) {
        return 10 + GetSizeOfCompactSize(num_outputs);
    };

    size_t ltc_recipient_bytes{0};
    for (const CRecipient& recipient : ltc_recipients) {
        ltc_recipient_bytes += ::GetSerializeSize(CTxOut(recipient.nAmount, recipient.GetScript()), PROTOCOL_VERSION);
    }
    const size_t mweb_recipient_weight = mw::STANDARD_OUTPUT_WEIGHT * mweb_recipients.size();
    const size_t standard_mweb_weight = mw::KERNEL_WITH_STEALTH_WEIGHT + mweb_recipient_weight;

    // Maximum size of a pegin output (in bytes)
    const size_t pegin_output_bytes = ::GetSerializeSize(
        CTxOut{MAX_MONEY, GetScriptForPegin(mw::Hash())}, PROTOCOL_VERSION);

    // Size (in bytes) of a hogex input - Equivalent to ::GetSerializeSize(CTxIn(), PROTOCOL_VERSION)
    const size_t hogex_input_bytes = 41;
    const size_t pegin_ltc_bytes = get_ltc_tx_overhead(1) + pegin_output_bytes + hogex_input_bytes;

    switch (tx_type) {
    case TxType::MWEB_TO_MWEB: {
        return recipients_sum + get_layered_fee(0, 0, standard_mweb_weight);
    }
    case TxType::PEGIN: {
        return recipients_sum + get_layered_fee(pegin_ltc_bytes, 0, standard_mweb_weight);
    }
    case TxType::PEGOUT: {
        // Include enough fee to pay for the kernel (with pegout script(s)), MWEB outputs, and the hogex pegout output(s).
        std::vector<PegOutCoin> pegouts;
        std::transform(
            ltc_recipients.cbegin(), ltc_recipients.cend(), std::back_inserter(pegouts),
            [](const CRecipient& recipient) { return PegOutCoin(recipient.nAmount, recipient.GetScript()); }
        );
        const size_t pegout_mweb_weight = Weight::CalcKernelWeight(true, pegouts) + mweb_recipient_weight;

        return recipients_sum + get_layered_fee(0, ltc_recipient_bytes, pegout_mweb_weight);
    }
    case TxType::PEGIN_PEGOUT: {
        // Include enough fee to pay for:
        // * LTC tx with a pegin output
        // * Hogex pegin input
        // * Hogex pegout output(s)
        // * MWEB recipient outputs
        // * Kernel (with pegin amount and pegout script(s))
        std::vector<PegOutCoin> pegouts;
        std::transform(
            ltc_recipients.cbegin(), ltc_recipients.cend(), std::back_inserter(pegouts),
            [](const CRecipient& recipient) { return PegOutCoin(recipient.nAmount, recipient.GetScript()); }
        );
        const size_t pegout_mweb_weight = Weight::CalcKernelWeight(true, pegouts) + mweb_recipient_weight;

        return recipients_sum + get_layered_fee(pegin_ltc_bytes, ltc_recipient_bytes, pegout_mweb_weight);
    }
    case TxType::LTC_TO_LTC: {
        const size_t ltc_bytes = get_ltc_tx_overhead(ltc_recipients.size()) + ltc_recipient_bytes;
        return recipients_sum + get_layered_fee(ltc_bytes, 0, 0);
    }
    }

    assert(false);
}

CAmount TxBuilder::GetFeePaid() const
{
    return GetTransactionAmounts(m_selected_coins, m_tx).GetFeePaid();
}

// Calculate the portion of the fee that should be paid on the LTC side.
util::Result<CAmount> TxBuilder::CalcLTCFee() const
{
    const TxType tx_type = GetTxType();
    if (tx_type == TxType::MWEB_TO_MWEB || tx_type == TxType::PEGOUT) {
        return CAmount{0};
    }
    CMutableTransaction tx_without_mweb = m_tx;
    tx_without_mweb.mweb_tx.SetNull();
    
    util::Result<TxSize> tx_size_result = CalcMaxSignedTxSize(tx_without_mweb);
    if (!tx_size_result) {
        return util::Error{ErrorString(tx_size_result)};
    }

    size_t tx_bytes = tx_size_result->vsize;
    if (tx_type == TxType::PEGIN || tx_type == TxType::PEGIN_PEGOUT) {
        // Add hogex input bytes
        tx_bytes += ::GetSerializeSize(CTxIn(), PROTOCOL_VERSION);
    }

    return GetFeeRate().GetFee(tx_bytes, 0);
}

CAmount TxBuilder::CalcMWEBFee() const noexcept
{
    size_t nBytes = 0;
    for (const PegOutCoin& pegout : m_tx.mweb_tx.GetPegOutCoins()) {
        nBytes += ::GetSerializeSize(CTxOut(pegout.GetAmount(), pegout.GetScriptPubKey()), PROTOCOL_VERSION);
    }

    return GetFeeRate().GetFee(nBytes, m_tx.mweb_tx.GetMWEBWeight());
}

util::Result<TxSize> TxBuilder::CalcMaxSignedTxSize(const CMutableTransaction& tx) const
{
    TxSize tx_sizes = CalculateMaximumSignedTxSize(CTransaction(tx), &m_wallet, &m_coin_control);
    int nBytes = tx_sizes.vsize;
    if (nBytes == -1) {
        return util::Error{_("Missing solving data for estimating transaction size")};
    }

    return tx_sizes;
}

} // namespace wallet
