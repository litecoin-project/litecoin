#include <wallet/txbuilder.h>

#include <consensus/validation.h>
#include <mw/wallet/sign.h>
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

namespace wallet {

TxBuilder::Ptr TxBuilder::New(const CWallet& wallet, const CCoinControl& coin_control, const std::vector<CRecipient>& recipients, const std::optional<int>& change_position)
{
    ChangeBuilder change = ChangeBuilder::New(wallet, coin_control, recipients, change_position);

    return TxBuilder::Ptr(new TxBuilder{wallet, coin_control, recipients, std::move(change)});
}

util::Result<CreatedTransactionResult> TxBuilder::Build(const std::optional<int32_t>& nVersion, const std::optional<uint32_t>& nLockTime, bool sign)
{
    LogPrintf(
        "DEBUG: START - nVersion=%s, nLockTime=%s, sign=%s\n",
        nVersion.has_value() ? std::to_string(*nVersion) : "NONE",
        nLockTime.has_value() ? std::to_string(*nLockTime) : "NONE",
        sign ? "TRUE" : "FALSE"
    );

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
    LogPrintf("DEBUG: Getting available coins\n");
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
    LogPrintf("DEBUG: Selecting coins\n");
    auto result = SelectInputCoins(available_coins);
    if (!result) {
        return util::Error{ErrorString(result)};
    }
    
    std::vector<GenericWalletUTXO> selected_coins = result->GetShuffledInputVector();
    TRACE5(coin_selection, selected_coins, m_wallet.GetName().c_str(), GetAlgorithmName(result->GetAlgo()).c_str(), result->GetTarget(), result->GetWaste(), result->GetSelectedValue());

    // Add selected inputs
    LogPrintf("DEBUG: Adding inputs\n");
    auto add_inputs_error = AddInputs(selected_coins);
    if (add_inputs_error.has_value()) {
        return add_inputs_error.value();
    }

    // Use a height-based locktime to discourage fee sniping. Skip this for MWEB_TO_MWEB and PEGOUT transactions, since they don't have a LTC transaction.
    if (!nLockTime.has_value() && !m_tx.vin.empty()) {
        DiscourageFeeSniping(m_tx, m_selection_params.rng_fast, m_wallet.chain(), m_wallet.GetLastBlockHash(), m_wallet.GetLastBlockHeight());
    }
    
    // Add outputs (recipients, change, pegin)
    auto add_outputs_error = AddOutputs(*result);
    if (add_outputs_error.has_value()) {
        return add_outputs_error.value();
    }

    LogPrintf("DEBUG: Calling CalcMaxSignedTxBytes\n");
    auto tx_size = CalcMaxSignedTxSize(m_tx);
    if (!tx_size) {
        return util::Error{ErrorString(tx_size)};
    }
    
    // Subtract fee from outputs
    auto subtract_fee_error = SubtractFeeFromOutputs();
    if (subtract_fee_error.has_value()) {
        return subtract_fee_error.value();
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

        LogPrintf("DEBUG: Signing tx\n");
        if (!m_wallet.SignTransaction(m_tx)) {
            return util::Error{_("Signing transaction failed")};
        }
    }

    // Return the constructed transaction data.
    CTransactionRef tx = MakeTransactionRef(CTransaction(m_tx));

    // Limit size
    if ((sign && GetTransactionWeight(*tx) > MAX_STANDARD_TX_WEIGHT) || (!sign && tx_size->weight > MAX_STANDARD_TX_WEIGHT))
    {
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
    
    m_wallet.WalletLogPrintf("Fee Calculation: Fee:%d Bytes:%d Tgt:%d (requested %d) Reason:\"%s\" Decay %.5f: Estimation: (%g - %g) %.2f%% %.1f/(%.1f %d mem %.1f out) Fail: (%g - %g) %.2f%% %.1f/(%.1f %d mem %.1f out)\n",
              fee_paid, tx_size->vsize, feeCalc.returnedTarget, feeCalc.desiredTarget, StringForFeeReason(feeCalc.reason), feeCalc.est.decay,
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
    auto select_by_type = [&](const TxType& tx_type) -> std::optional<SelectionResult> {
        m_selection_params.m_tx_type = tx_type;

        auto change_params = m_change.BuildParams(m_wallet, m_coin_control, m_selection_params, m_recipients);
        if (!change_params) return {};
        m_selection_params.m_change_params = *change_params;

        const CAmount nTarget = CalcSelectionTarget(tx_type);
        CoinsResult available_coins_mut = available_coins;

        LogPrintf("DEBUG: Selection target: %s, Change on MWEB: %i, tx_type: %d\n", FormatMoney(nTarget), ChangeBuilder::ChangeBelongsOnMWEB(tx_type, m_coin_control.destChange), (int)tx_type);
        return SelectCoins(m_wallet, available_coins_mut, nTarget, m_coin_control, m_selection_params);
    };
    
    // MW: TODO - Handle manually selected inputs that conflict with TxType
    if (!m_recipients.MWEB().empty()) {
        // MW: TODO - Fail if LTC change is set, or make it work properly

        // First try to construct an MWEB-to-MWEB transaction
        std::optional<SelectionResult> mweb_to_mweb_result = select_by_type(TxType::MWEB_TO_MWEB);
        if (mweb_to_mweb_result.has_value()) {
            LogPrintf("DEBUG: MWEB_TO_MWEB\n");
            return *mweb_to_mweb_result;
        }

        // If MWEB-to-MWEB fails, create a peg-in transaction
        std::optional<SelectionResult> pegin_result = select_by_type(TxType::PEGIN);
        if (pegin_result.has_value()) {
            LogPrintf("DEBUG: PEGIN\n");
            return *pegin_result;
        }
    } else {
        // First try to construct a LTC-to-LTC transaction
        std::optional<SelectionResult> ltc_to_ltc_result = select_by_type(TxType::LTC_TO_LTC);
        if (ltc_to_ltc_result.has_value()) {
            LogPrintf("DEBUG: LTC_TO_LTC\n");
            return *ltc_to_ltc_result;
        }

        // If LTC-to-LTC fails, try a simple peg-out transaction (MWEB->LTC)
        std::optional<SelectionResult> mweb_to_ltc_result = select_by_type(TxType::PEGOUT);
        if (mweb_to_ltc_result.has_value()) {
            LogPrintf("DEBUG: PEGOUT\n");
            return *mweb_to_ltc_result;
        }

        // If simple peg-out fails, try a complex peg-out transaction (LTC->MWEB->LTC)
        std::optional<SelectionResult> pegin_pegout_result =  select_by_type(TxType::PEGIN_PEGOUT);
        if (pegin_pegout_result.has_value()) {
            LogPrintf("DEBUG: PEGIN_PEGOUT\n");
            return *pegin_pegout_result;
        }
    }

    return util::Error{_("Insufficient funds")};
}

std::optional<util::Error> TxBuilder::AddInputs(const std::vector<GenericWalletUTXO>& shuffled_inputs)
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
    for (const GenericWalletUTXO& utxo : shuffled_inputs) {
        if (utxo.IsMWEB()) {
            m_tx.mweb_tx.inputs.push_back(mw::MutableInput::FromCoin(utxo.GetMWEB().coin));
        } else {
            m_tx.vin.push_back(CTxIn(utxo.GetID().ToOutPoint(), CScript(), nSequence));
        }
    }

    return std::nullopt;
}

std::optional<util::Error> TxBuilder::AddOutputs(const SelectionResult& selection_result)
{
    LogPrintf("DEBUG: BEGIN\n");

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
    LogPrintf(
        "DEBUG: Getting change - Selected value: %s, effective value: %s, diff(i.e. input fee): %lld, change_fee: %lld\n",
        FormatMoney(selection_result.GetSelectedValue()),
        FormatMoney(selection_result.GetSelectedEffectiveValue()),
        selection_result.GetSelectedValue() - selection_result.GetSelectedEffectiveValue(),
        m_selection_params.m_change_params.m_change_fee
    );
    const CAmount change_amount = selection_result.GetChange(m_selection_params.m_change_params.min_viable_change, m_selection_params.m_change_params.m_change_fee);
    LogPrintf("DEBUG: change_amount: %s\n", FormatMoney(change_amount));
    if (change_amount > 0) {
        m_change.amount = change_amount;
        if (ChangeBuilder::ChangeBelongsOnMWEB(tx_type, m_coin_control.destChange)) {
            LogPrintf("DEBUG: Change on MWEB\n");
            if (!m_change.script_or_address.IsMWEB()) {
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
            LogPrintf("DEBUG: Change on LTC\n");
            CTxOut newTxOut(change_amount, m_change.script_or_address.GetScript()); // MW: TODO - What if script_or_address is MWEB address?
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
    } else {
        m_change.amount = 0;
        m_change.change_position.SetNull();
    }

    // Add peg-in output for PEGIN and PEGIN_PEGOUT transactions
    if (tx_type == TxType::PEGIN || tx_type == TxType::PEGIN_PEGOUT) {
        LogPrintf("DEBUG: Adding pegin\n");

        if (!m_change.change_position.IsMWEB()) {
            // Pegin amount needed when no MWEB change = (MWEB fee + MWEB output values) - (MWEB input values + Pegout values).
            CAmount pegin_amount = CalcMWEBFee();
            for (const mw::MutableOutput& mweb_output : m_tx.mweb_tx.outputs) {
                pegin_amount += mweb_output.amount.value_or(0);
            }

            for (const GenericWalletUTXO& input : selection_result.GetInputSet()) {
                if (input.IsMWEB()) {
                    pegin_amount -= input.GetValue();
                }
            }

            pegin_amount -= m_tx.mweb_tx.GetTotalPegoutAmount();

            m_tx.mweb_tx.SetPeginAmount(pegin_amount);
            m_tx.vout.push_back(CTxOut{pegin_amount, GetScriptForPegin(mw::Hash())});
        } else {
            CAmount pegin_amount{0};
            for (const GenericWalletUTXO& input : selection_result.GetInputSet()) {
                if (!input.IsMWEB()) {
                    pegin_amount += input.GetValue();
                }
            }

            m_tx.mweb_tx.SetPeginAmount(pegin_amount);
            m_tx.vout.push_back(CTxOut{pegin_amount, GetScriptForPegin(mw::Hash())});
            CTxOut& pegin_output = m_tx.vout.back();

            // Reduce the pegin amount by ltc_fee
            const util::Result<CAmount> ltc_fee_result = CalcLTCFee();
            if (!ltc_fee_result) {
                return util::Error{ErrorString(ltc_fee_result)};
            }

            pegin_output.nValue -= ltc_fee_result.value();
            m_tx.mweb_tx.SetPeginAmount(pegin_output.nValue);
            LogPrintf("DEBUG: pegin_amount: %s, ltc_fee: %lld, change_amount: %s\n", FormatMoney(pegin_output.nValue), *ltc_fee_result, FormatMoney(m_change.amount));

            // Error if the pegin output is reduced to be below dust
            if (pegin_output.nValue < 0) {
                return util::Error{_("The transaction amount is too small to pay the fee")};
            } else if (IsDust(pegin_output, m_wallet.chain().relayDustFee())) {
                return util::Error{_("The transaction amount is too small to send after the fee has been deducted")};
            }
        }
    }

    LogPrintf("DEBUG: END\n");
    return std::nullopt;
}

std::optional<util::Error> TxBuilder::SubtractFeeFromOutputs()
{
    LogPrintf("DEBUG: BEGIN\n");
    util::Result<CAmount> ltc_fee_result = CalcLTCFee();
    if (!ltc_fee_result) {
        return util::Error{ErrorString(ltc_fee_result)};
    }

    CAmount mweb_fee = CalcMWEBFee();
    CAmount fee_needed = *ltc_fee_result + mweb_fee;
    CAmount current_fee = GetFeePaid();
    LogPrintf("DEBUG: fee_needed: %lld (%lld LTC, %lld MWEB), current_fee: %lld\n", fee_needed, *ltc_fee_result, mweb_fee, current_fee);

    // If there is a change output and we overpay the fees then increase the change to match the fee needed
    if (!m_change.GetPosition().IsNull() && fee_needed < current_fee) {
        if (m_change.GetPosition().IsLTC()) {
            auto& change = m_tx.vout.at(m_change.GetPosition().ToLTC());
            change.nValue += current_fee - fee_needed;
        } else {
            m_change.amount += current_fee - fee_needed;
            mw::MutableOutput& change_output = m_tx.mweb_tx.outputs.back();
            *change_output.amount += current_fee - fee_needed;
            LogPrintf("DEBUG: change amount: %s = %s, updated fee_paid: %lld\n", FormatMoney(m_change.amount), FormatMoney(*change_output.amount), GetFeePaid());
        }
        current_fee = fee_needed;
    }

    // The only time that fee_needed should be less than the amount available for fees is when
    // we are subtracting the fee from the outputs. If this occurs at any other time, it is a bug.
    assert(m_selection_params.m_subtract_fee_outputs || fee_needed <= current_fee);

    const CAmount to_reduce = fee_needed - current_fee;
    const size_t outputs_to_subtract_fee_from = m_recipients.NumOutputsToSubtractFeeFrom();

    bool fFirst = true;

    if (m_tx.mweb_tx.GetPegouts().empty()) {
        size_t i = 0;
        for (const auto& recipient : m_recipients.LTC()) {
            ChangePosition change_pos = m_change.GetPosition();
            if (change_pos == i) {
                i++;
            }

            CTxOut& txout = m_tx.vout[i];
            if (recipient.fSubtractFeeFromAmount) {
                txout.nValue -= to_reduce / outputs_to_subtract_fee_from; // Subtract fee equally from each selected recipient

                // first receiver pays the remainder not divisible by output count
                if (fFirst) {
                    fFirst = false;
                    txout.nValue -= to_reduce % outputs_to_subtract_fee_from;
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

    LogPrintf("DEBUG: Subtracting from MWEB outputs\n");
    for (mw::MutableOutput& output : m_tx.mweb_tx.outputs) {
        if (output.subtract_fee_from_amount.value_or(false)) {
            assert(output.amount.has_value()); // MW: TODO - Need to verify in VerifyRecipients that output has amount
            *output.amount -= to_reduce / outputs_to_subtract_fee_from;

            if (fFirst) {
                fFirst = false;
                *output.amount -= to_reduce % outputs_to_subtract_fee_from;
            }
        }

        if (*output.amount < 0) {
            return util::Error{_("The transaction amount is too small to pay the fee")};
        }
    }

    LogPrintf("DEBUG: Subtracting from pegouts\n");
    for (mw::MutableKernel& kernel : m_tx.mweb_tx.kernels) {
        for (mw::PegOutRecipient& recipient : kernel.pegouts) {
            if (recipient.fSubtractFeeFromAmount) {
                recipient.nAmount -= to_reduce / outputs_to_subtract_fee_from;

                if (fFirst) {
                    fFirst = false;
                    recipient.nAmount -= to_reduce % outputs_to_subtract_fee_from;
                }
            }

            if (recipient.nAmount < 0) {
                return util::Error{_("The transaction amount is too small to pay the fee")};
            } else if (IsDust(CTxOut(recipient.nAmount, recipient.script), m_wallet.chain().relayDustFee())) {
                return util::Error{_("The transaction amount is too small to send after the fee has been deducted")};
            }
        }
    }

    LogPrintf("DEBUG: END\n");
    return std::nullopt;
}

std::optional<util::Error> TxBuilder::SignMWEBTx()
{
    LogPrintf("DEBUG: BEGIN\n");
    if (GetTxType() == TxType::LTC_TO_LTC) {
        LogPrintf("DEBUG: Not an MWEB Tx. Nothing to sign\n");
        return std::nullopt;
    }

    util::Result<mw::SignTxResult> sign_tx_result = mw::SignTx(m_tx);
    if (!sign_tx_result) {
        return util::Error{util::ErrorString(sign_tx_result)};
    }

    LogPrintf("DEBUG: MWEB transaction signed\n");

    // Update change position
    if (m_change.change_position.IsMWEB()) {
        for (const mw::MutableOutput& output : m_tx.mweb_tx.outputs) {
            if (output.address.has_value() && *output.address == m_change.script_or_address.GetMWEBAddress()) {
                m_change.change_position = MWEBChangePosition{m_tx.mweb_tx.outputs.size(), output.CalcOutputID()};
                break;
            }
        }
    }

    if (!sign_tx_result->coins_by_output_id.empty()) {
        std::vector<mw::Coin> mweb_coins;
        std::transform(
            sign_tx_result->coins_by_output_id.cbegin(), sign_tx_result->coins_by_output_id.cend(), std::back_inserter(mweb_coins),
            [](const std::pair<mw::Hash, mw::Coin>& entry) { return entry.second; });
        m_wallet.GetMWWallet()->SaveToWallet(mweb_coins); // MW: TODO - This should only be done in CommitTransaction, since this could be called with add_to_wallet=false
    }

    // TxBuilder::BuildTx only builds partial coins.
    // We still need to rewind them to populate any remaining fields, like address index.
    m_wallet.GetMWWallet()->RewindOutputs(CTransaction(m_tx));

    LogPrintf("DEBUG: END\n");
    return std::nullopt;
}

CAmount TxBuilder::CalcSelectionTarget(const TxType& tx_type) const
{
    LogPrintf("DEBUG: Calculating target for type: %d\n", (int)tx_type);

    const CAmount recipients_sum = m_recipients.Sum();
    if (m_selection_params.m_subtract_fee_outputs) {
        return recipients_sum;
    }

    std::vector<CRecipient> ltc_recipients = m_recipients.LTC();
    std::vector<CRecipient> mweb_recipients = m_recipients.MWEB();
    
    // Static vsize overhead + outputs vsize. 4 nVersion, 4 nLocktime, 1 input count, 1 witness overhead (dummy, flag, stack size), and bytes for output count
    size_t num_ltc_recipients = ltc_recipients.size();
    if (tx_type == TxType::PEGIN || tx_type == TxType::PEGIN_PEGOUT) {
        ++num_ltc_recipients;
    }
    const size_t base_ltc_bytes = 10 + GetSizeOfCompactSize(num_ltc_recipients);

    size_t ltc_recipient_bytes{0};
    for (const auto& recipient : ltc_recipients) {
        ltc_recipient_bytes += ::GetSerializeSize(CTxOut(recipient.nAmount, recipient.GetScript()), PROTOCOL_VERSION);
    }

    // Maximum size of a pegin output (in bytes)
    const size_t pegin_output_bytes = ::GetSerializeSize(CTxOut{MAX_MONEY, GetScriptForPegin(mw::Hash())}, PROTOCOL_VERSION);

    // Size (in bytes) of a hogex input - Equivalent to ::GetSerializeSize(CTxIn(), PROTOCOL_VERSION)
    const size_t hogex_input_bytes = 41;

    switch (tx_type) {
    case TxType::MWEB_TO_MWEB: {
        const size_t mweb_weight = mw::KERNEL_WITH_STEALTH_WEIGHT + (mw::STANDARD_OUTPUT_WEIGHT * mweb_recipients.size());
        const CAmount non_change_mweb_fee = GetFeeRate().GetFee(0, mweb_weight);
        return recipients_sum + non_change_mweb_fee;
    }
    case TxType::PEGIN: {
        const size_t pegin_bytes = base_ltc_bytes + pegin_output_bytes + hogex_input_bytes;
        const size_t pegin_mweb_weight = mw::KERNEL_WITH_STEALTH_WEIGHT + (mw::STANDARD_OUTPUT_WEIGHT * mweb_recipients.size());
        const CAmount pegin_fee = GetFeeRate().GetFee(pegin_bytes, pegin_mweb_weight);
        LogPrintf("DEBUG: Max LTC bytes: %u, MWEB weight: %u, pegin_fee: %lld\n", pegin_bytes, pegin_mweb_weight, pegin_fee);
        return recipients_sum + pegin_fee;
    }
    case TxType::PEGOUT: {
        // Include enough fee to pay for the kernel (with pegout script(s)) and the hogex pegout output(s).
        std::vector<PegOutCoin> pegouts;
        std::transform(
            ltc_recipients.cbegin(), ltc_recipients.cend(), std::back_inserter(pegouts),
            [](const CRecipient& recipient) { return PegOutCoin(recipient.nAmount, recipient.GetScript()); }
        );
        const size_t pegout_kernel_weight = Weight::CalcKernelWeight(true, pegouts);

        const CAmount basic_pegout_fee = GetFeeRate().GetFee(ltc_recipient_bytes, pegout_kernel_weight);
        return recipients_sum + basic_pegout_fee;
    }
    case TxType::PEGIN_PEGOUT: {
        // Include enough fee to pay for:
        // * LTC tx with a pegin output
        // * Hogex pegin input
        // * Hogex pegout output(s)
        // * Kernel (with pegin amount and pegout script(s))
        std::vector<PegOutCoin> pegouts;
        std::transform(
            ltc_recipients.cbegin(), ltc_recipients.cend(), std::back_inserter(pegouts),
            [](const CRecipient& recipient) { return PegOutCoin(recipient.nAmount, recipient.GetScript()); }
        );
        const size_t pegout_kernel_weight = Weight::CalcKernelWeight(true, pegouts);

        const size_t pegin_bytes = base_ltc_bytes + pegin_output_bytes + hogex_input_bytes + ltc_recipient_bytes;
        const CAmount complex_pegout_fee = GetFeeRate().GetFee(pegin_bytes, pegout_kernel_weight);
        return recipients_sum + complex_pegout_fee;
    }
    case TxType::LTC_TO_LTC: {
        const CAmount ltc_to_ltc_fee = GetFeeRate().GetFee(base_ltc_bytes + ltc_recipient_bytes, 0);
        return recipients_sum + ltc_to_ltc_fee;
    }
    }

    assert(false);
}

CAmount TxBuilder::GetFeePaid() const
{
    const CAmount ltc_input_sum = std::accumulate(
        m_selected_coins.cbegin(), m_selected_coins.cend(), CAmount{0},
        [](CAmount sum, const GenericWalletUTXO& coin) { return coin.IsMWEB() ? sum : (sum + coin.GetValue()); }
    );
    const CAmount ltc_output_sum = std::accumulate(
        m_tx.vout.cbegin(), m_tx.vout.cend(), CAmount{0},
        [](CAmount sum, const CTxOut& txout) { return sum += txout.nValue; }
    );
    const CAmount ltc_fee = ltc_input_sum - ltc_output_sum;
    LogPrintf("DEBUG: ltc_input_sum: %s, ltc_output_sum: %s, ltc_fee: %lld\n", FormatMoney(ltc_input_sum), FormatMoney(ltc_output_sum), ltc_fee);
    assert(ltc_input_sum >= ltc_output_sum);

    const CAmount mweb_input_sum = std::accumulate(
        m_selected_coins.cbegin(), m_selected_coins.cend(), CAmount{0},
        [](CAmount sum, const GenericWalletUTXO& coin) { return coin.IsMWEB() ? (sum + coin.GetValue()) : sum; }
    );
    const CAmount mweb_pegin = m_tx.mweb_tx.GetPeginAmount().value_or(0);
    const CAmount mweb_output_sum = std::accumulate(
        m_tx.mweb_tx.outputs.cbegin(), m_tx.mweb_tx.outputs.cend(), CAmount{0},
        [](CAmount sum, const mw::MutableOutput& output) { return sum += output.amount.value_or(0); }
    );
    std::vector<mw::PegOutRecipient> pegouts = m_tx.mweb_tx.GetPegouts();
    const CAmount mweb_pegout_sum = std::accumulate(
        pegouts.cbegin(), pegouts.cend(), CAmount{0},
        [](CAmount sum, const mw::PegOutRecipient& recipient) { return sum += recipient.nAmount; }
    );
    LogPrintf("DEBUG: mweb_input_sum: %s, mweb_pegin: %s, mweb_output_sum: %s, mweb_pegout_sum: %s\n", FormatMoney(mweb_input_sum), FormatMoney(mweb_pegin), FormatMoney(mweb_output_sum), FormatMoney(mweb_pegout_sum));
    const CAmount mweb_fee = (mweb_input_sum + mweb_pegin) - (mweb_output_sum + mweb_pegout_sum);
    // if mweb_fee is negative then this reduces the current fee paid so that later we will reduce output values by an additional |mweb_fee|. This happens for peg-ins when m_subtract_fee_outputs is true.

    return ltc_fee + mweb_fee;
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
    if (m_tx.mweb_tx.GetPeginAmount().has_value()) {
        // Add hogex input bytes
        tx_bytes += ::GetSerializeSize(CTxIn(), PROTOCOL_VERSION);
    }

    LogPrintf(
        "DEBUG: tx_size: %lld, with_hogex: %llu, inputs: %llu, outputs: %llu\n",
        tx_size_result->vsize,
        tx_bytes,
        tx_without_mweb.vin.size(),
        tx_without_mweb.vout.size()
    );
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
