#pragma once

#include <primitives/transaction.h>
#include <script/address.h>
#include <util/result.h>
#include <wallet/change.h>
#include <wallet/coincontrol.h>
#include <wallet/recipient.h>
#include <wallet/reserve.h>
#include <wallet/spend.h>
#include <wallet/utxo.h>
#include <wallet/wallet.h>

namespace wallet {

class TxBuilder
{
    const CWallet& m_wallet;
    const CCoinControl& m_coin_control;
    FastRandomContext m_rng_fast;
    CoinSelectionParams m_selection_params;
    CRecipients m_recipients;

    // Mutable fields
    std::vector<AnyWalletUTXO> m_selected_coins;
    CMutableTransaction m_tx;
    ChangeBuilder m_change;

public:
    using Ptr = std::shared_ptr<TxBuilder>;

    static TxBuilder::Ptr New(const CWallet& wallet, const CCoinControl& coin_control, const std::vector<CRecipient>& recipients, const std::optional<int>& change_position);

    util::Result<CreatedTransactionResult> Build(const std::optional<int32_t>& nVersion, const std::optional<uint32_t>& nLockTime, bool sign) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet);

private:
    TxBuilder(const CWallet& wallet, const CCoinControl& coin_control, std::vector<CRecipient> recipients, ChangeBuilder&& change)
        : m_wallet(wallet), m_coin_control(coin_control), m_rng_fast{}, m_selection_params{m_rng_fast}, m_recipients(std::move(recipients)), m_tx(), m_change(std::move(change)) { }
    
    // Attempts to select inputs from the available coins provided.
    // 
    // When recipients are MWEB addresses:
    // 1. Select only MWEB inputs in order to create an MWEB->MWEB transaction.
    // 2. Select LTC and (optionally) MWEB inputs in order to create a LTC->MWEB pegin transaction.
    // 
    // When recipients are LTC addresses:
    // 1. Select only LTC inputs in order to create a LTC->LTC transaction.
    // 2. Select only MWEB inputs in order to create a MWEB->LTC pegout transaction.
    // 3. Select LTC and MWEB inputs in order to create a LTC->MWEB->LTC pegin-pegout transaction.
    util::Result<SelectionResult> SelectInputCoins(const CoinsResult& available_coins) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet);
    
    CAmount CalcSelectionTarget(const TxType& tx_type) const;

    void AddInputs(const std::vector<AnyWalletUTXO>& shuffled_inputs);
    std::optional<util::Error> AddOutputs(const SelectionResult& selection_result) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet);
    std::optional<util::Error> AddChangeOutput(const SelectionResult& selection_result);
    std::optional<util::Error> AddPeginOutput(const SelectionResult& selection_result) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet);
    std::optional<util::Error> UpdatePeginOutput(const SelectionResult& selection_result) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet);
    void GrowChangeBy(const CAmount growth_amount);
    std::optional<util::Error> SubtractFeeFromOutputs(const CAmount fee_to_distribute);
    std::optional<util::Error> SignMWEBTx() EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet);

    TxType GetTxType() const noexcept { return m_selection_params.m_tx_type; }

    // Returns the sum of fees paid on the LTC side and the MWEB side.
    // fee_paid = (sum(LTC inputs) - sum(LTC outputs)) + sum(MWEB kernel fees)
    CAmount GetFeePaid() const;

    // The effective fee rate.
    const CFeeRate& GetFeeRate() const noexcept { return m_selection_params.m_effective_feerate; }

    // The fee to be paid on the LTC side
    util::Result<CAmount> CalcLTCFee() const EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet);

    // The fee to be paid on the MWEB side.
    // This includes all MWEB inputs, outputs, and kernels, as well as any HogEx outputs for pegouts.
    CAmount CalcMWEBFee() const noexcept;

    util::Result<TxSize> CalcMaxSignedTxSize(const CMutableTransaction& tx) const EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet);
};

} // namespace wallet
