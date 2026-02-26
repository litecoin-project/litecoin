#include <policy/policy.h>
#include <util/check.h>
#include <util/rbf.h>
#include <wallet/change.h>
#include <wallet/spend.h>
#include <wallet/txbuilder.h>

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

    // Get size of spending the change output
    const int maximum_signed_input_size = CalculateMaximumSignedInputSize(change_prototype_txout, &wallet);
    
    // Size of the input to spend a change output in virtual bytes.
    // If the wallet doesn't know how to sign change output, assume p2sh-p2wpkh as lower-bound to allow BnB to do it's thing
    const size_t change_spend_size = (maximum_signed_input_size == -1) ? DUMMY_NESTED_P2WPKH_INPUT_SIZE : (size_t)maximum_signed_input_size;
    
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

std::optional<ChangeParams> ChangeBuilder::BuildParams(const CWallet& wallet, const CCoinControl& coin_control, const CoinSelectionParams& coin_selection_params, const CRecipients& recipients) const
{
    bool change_is_set = !std::holds_alternative<CNoDestination>(coin_control.destChange);
    bool change_is_mweb = std::holds_alternative<StealthAddress>(coin_control.destChange);

    if (ChangeBuilder::ChangeBelongsOnMWEB(coin_selection_params.m_tx_type, coin_control.destChange)) {
        if (change_is_set && !change_is_mweb) return {};
        return BuildMWEBParams(coin_selection_params);
    } else {
        if (change_is_set && change_is_mweb) return {};
        return BuildLTCParams(wallet, coin_selection_params, recipients);
    }
}

bool ChangeBuilder::ChangeBelongsOnMWEB(const TxType& tx_type, const CTxDestination& dest_change)
{
    switch (tx_type) {
        case TxType::LTC_TO_LTC:
        return false;
    case TxType::MWEB_TO_MWEB:
        return true;
    case TxType::PEGOUT:
    case TxType::PEGIN_PEGOUT:
        // return true;
    case TxType::PEGIN:
        return std::holds_alternative<CNoDestination>(dest_change) || std::holds_alternative<StealthAddress>(dest_change);
    }

    assert(false);
}

} // namespace wallet
