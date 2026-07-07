#include <mw/consensus/Weight.h>
#include <policy/policy.h>
#include <util/check.h>
#include <util/rbf.h>
#include <wallet/change.h>
#include <wallet/spend.h>
#include <wallet/txbuilder.h>

#include <algorithm>
#include <cmath>

namespace wallet {

ChangeBuilder ChangeBuilder::New(const CWallet& wallet, const CCoinControl& coin_control, const CRecipients& recipients, const std::optional<int>& change_position)
{
    ChangeBuilder change_builder;

    if (change_position.has_value() && change_position.value() >= 0) {
        change_builder.change_position = ChangePosition{(size_t)change_position.value()};
    }

    // coin control: send change to custom address
    if (!std::get_if<CNoDestination>(&coin_control.destChange)) {
        change_builder.script_or_address = GenericAddress(coin_control.destChange);
    } else { // no coin control: send change to newly generated address
        // Note: We use a new key here to keep it from being obvious which side is the change.
        //  The drawback is that by not reusing a previous key, the change may be lost if a
        //  backup is restored, if the backup doesn't have the new private key for the change.
        //  If we reused the old key, it would be possible to add code to look for and
        //  rediscover unknown transactions that were written with keys of ours to recover
        //  post-backup change.
        // Reserve a new key pair from key pool. If it fails, provide a dummy
        // destination in case we don't need change.
        CTxDestination dest;
    
        const OutputType change_type = wallet.TransactionChangeType(coin_control.m_change_type ? *coin_control.m_change_type : wallet.m_default_change_type, recipients.All());
        change_builder.reserve_dest = std::make_shared<ReserveDestination>(&wallet, change_type);
        auto op_dest = change_builder.reserve_dest->GetReservedDestination(true);
        if (!op_dest) {
            change_builder.error = _("Transaction needs a change address, but we can't generate it.") + Untranslated(" ") + util::ErrorString(op_dest);
        } else {
            dest = *op_dest;
            change_builder.script_or_address = GenericAddress(dest);
        }
        // A valid destination implies a change script (and
        // vice-versa). An empty change script will abort later, if the
        // change keypool ran out, but change is required.
        CHECK_NONFATAL(IsValidDestination(dest) != change_builder.script_or_address.IsEmpty());
    }

    return change_builder;
}

ChangeParams ChangeBuilder::BuildMWEBParams(const CoinSelectionParams& coin_selection_params) const
{
    ChangeParams mweb_change_params;
    mweb_change_params.min_viable_change = 0;
    mweb_change_params.m_change_fee = coin_selection_params.m_effective_feerate.GetFee(0, mw::STANDARD_OUTPUT_WEIGHT);
    mweb_change_params.m_cost_of_change = mweb_change_params.m_change_fee; // Spending MWEB inputs is free, so cost of change is just the change fee.
    mweb_change_params.m_min_change_target = 0;
    return mweb_change_params;
}

ChangeParams ChangeBuilder::BuildLTCParams(const CWallet& wallet, const CoinSelectionParams& coin_selection_params, const CRecipients& recipients) const
{
    CTxOut change_prototype_txout(0, this->script_or_address.GetScript());
    const uint32_t change_output_size = GetSerializeSize(change_prototype_txout);
    const size_t change_spend_size = GetChangeSpendSize(wallet, change_prototype_txout);
    
    ChangeParams change_params;

    // Calculate the cost of change
    // Cost of change is the cost of creating the change output + cost of spending the change output in the future.
    // For creating the change output now, we use the effective feerate.
    // For spending the change output in the future, we use the discard feerate for now.
    // So cost of change = (change output size * effective feerate) + (size of spending change output * discard feerate)
    change_params.m_change_fee = coin_selection_params.m_effective_feerate.GetFee(change_output_size, 0);
    change_params.m_cost_of_change = coin_selection_params.m_discard_feerate.GetFee(change_spend_size, 0) + change_params.m_change_fee;
    change_params.m_min_change_target = GenerateChangeTarget(std::floor(recipients.Sum() / recipients.size()), change_params.m_change_fee, coin_selection_params.rng_fast);

    // The smallest change amount should be:
    // 1. at least equal to dust threshold
    // 2. at least 1 sat greater than fees to spend it at m_discard_feerate
    const auto dust = GetDustThreshold(change_prototype_txout, coin_selection_params.m_discard_feerate);
    const auto change_spend_fee = coin_selection_params.m_discard_feerate.GetFee(change_spend_size, 0);
    change_params.min_viable_change = std::max(change_spend_fee + 1, dust);

    return change_params;
}

ChangeParams ChangeBuilder::BuildPegoutParams(const CWallet& wallet, const CoinSelectionParams& coin_selection_params, const CRecipients& recipients) const
{
    const CScript change_script = this->script_or_address.GetScript();
    CTxOut change_prototype_txout(0, change_script);
    const uint32_t pegout_output_size = GetSerializeSize(change_prototype_txout);
    const size_t change_spend_size = GetChangeSpendSize(wallet, change_prototype_txout);

    // The transaction already pays for a stealth kernel for PEGOUT/PEGIN_PEGOUT.
    // Change adds one HogEx output plus the extra kernel weight for its pegout script.
    const size_t pegout_kernel_weight_delta = Weight::CalcKernelWeight(true, change_script) - Weight::CalcKernelWeight(true, CScript{});

    ChangeParams change_params;
    change_params.m_change_fee = coin_selection_params.m_effective_feerate.GetFee(pegout_output_size, pegout_kernel_weight_delta);
    change_params.m_cost_of_change = coin_selection_params.m_discard_feerate.GetFee(change_spend_size, 0) + change_params.m_change_fee;
    change_params.m_min_change_target = GenerateChangeTarget(std::floor(recipients.Sum() / recipients.size()), change_params.m_change_fee, coin_selection_params.rng_fast);

    // Pegout change becomes a normal LTC UTXO, so its viability is the same as other LTC change.
    const auto dust = GetDustThreshold(change_prototype_txout, coin_selection_params.m_discard_feerate);
    const auto change_spend_fee = coin_selection_params.m_discard_feerate.GetFee(change_spend_size, 0);
    change_params.min_viable_change = std::max(change_spend_fee + 1, dust);

    return change_params;
}

std::optional<ChangeParams> ChangeBuilder::BuildParams(const CWallet& wallet, const CCoinControl& coin_control, const CoinSelectionParams& coin_selection_params, const CRecipients& recipients) const
{
    const std::optional<ChangePlacement> change_placement = GetChangePlacement(coin_selection_params.m_tx_type, coin_control.destChange);
    if (!change_placement.has_value()) {
        return {};
    }

    if ((*change_placement == ChangePlacement::LTC || *change_placement == ChangePlacement::PEGOUT) && script_or_address.IsMWEB()) {
        return {};
    }

    switch (*change_placement) {
    case ChangePlacement::MWEB:
        return BuildMWEBParams(coin_selection_params);
    case ChangePlacement::LTC:
        return BuildLTCParams(wallet, coin_selection_params, recipients);
    case ChangePlacement::PEGOUT:
        return BuildPegoutParams(wallet, coin_selection_params, recipients);
    }

    assert(false);
    return {};
}

bool ChangeBuilder::ChangeBelongsOnMWEB(const TxType& tx_type, const CTxDestination& dest_change)
{
    const std::optional<ChangePlacement> change_placement = GetChangePlacement(tx_type, dest_change);
    return change_placement.has_value() && *change_placement == ChangePlacement::MWEB;
}

bool ChangeBuilder::ChangeBelongsOnPegout(const TxType& tx_type, const CTxDestination& dest_change)
{
    const std::optional<ChangePlacement> change_placement = GetChangePlacement(tx_type, dest_change);
    return change_placement.has_value() && *change_placement == ChangePlacement::PEGOUT;
}

std::optional<ChangeBuilder::ChangePlacement> ChangeBuilder::GetChangePlacement(const TxType& tx_type, const CTxDestination& dest_change)
{
    const bool change_is_set = !std::holds_alternative<CNoDestination>(dest_change);
    const bool change_is_mweb = std::holds_alternative<StealthAddress>(dest_change);

    switch (tx_type) {
    case TxType::LTC_TO_LTC:
        return change_is_set && change_is_mweb ? std::nullopt : std::make_optional(ChangePlacement::LTC);
    case TxType::MWEB_TO_MWEB:
        return change_is_set && !change_is_mweb ? std::nullopt : std::make_optional(ChangePlacement::MWEB);
    case TxType::PEGIN:
        return change_is_set && !change_is_mweb ? std::make_optional(ChangePlacement::LTC) : std::make_optional(ChangePlacement::MWEB);
    case TxType::PEGOUT:
    case TxType::PEGIN_PEGOUT:
        return change_is_set && !change_is_mweb ? std::make_optional(ChangePlacement::PEGOUT) : std::make_optional(ChangePlacement::MWEB);
    }

    assert(false);
    return std::nullopt;
}

size_t ChangeBuilder::GetChangeSpendSize(const CWallet& wallet, const CTxOut& change_prototype_txout)
{
    const int maximum_signed_input_size = CalculateMaximumSignedInputSize(change_prototype_txout, &wallet);

    // Size of the input to spend a change output in virtual bytes.
    // If the wallet doesn't know how to sign change output, assume p2sh-p2wpkh as lower-bound to allow BnB to do it's thing.
    return (maximum_signed_input_size == -1) ? DUMMY_NESTED_P2WPKH_INPUT_SIZE : (size_t)maximum_signed_input_size;
}

} // namespace wallet
