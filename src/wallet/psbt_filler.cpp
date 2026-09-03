// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/psbt_filler.h>

#include <mweb/mweb_wallet.h>
#include <script/descriptor.h>
#include <util/translation.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>

#include <algorithm>

namespace wallet {
namespace {

std::optional<std::string> InferMWEBAddressDescriptor(const CWallet& wallet, const mw::WalletCoin& coin)
{
    const std::shared_ptr<MWEB::Wallet>& mweb_wallet = wallet.GetMWWallet();
    if (!mweb_wallet) {
        return std::nullopt;
    }

    StealthAddress address;
    if (!mweb_wallet->GetStealthAddress(coin, address)) {
        return std::nullopt;
    }

    const GenericAddress generic_address(address);
    std::unique_ptr<SigningProvider> provider = wallet.GetSolvingProvider(generic_address);
    if (!provider) {
        return std::nullopt;
    }

    std::unique_ptr<Descriptor> descriptor = InferDescriptor(generic_address, *provider);
    if (!descriptor || descriptor->GetOutputType() != OutputType::MWEB || descriptor->IsRange()) {
        return std::nullopt;
    }

    return descriptor->ToString();
}

//! Adapter exposing the narrow view of CWallet state that MWEB PSBT input key
//! resolution needs (see wallet/mweb_psbt.h).
class WalletMWEBKeyStore final : public MWEBSigningKeyStore
{
public:
    explicit WalletMWEBKeyStore(const CWallet& wallet) : m_wallet(wallet) {}

    std::optional<mw::WalletCoin> GetWalletCoin(const mw::Hash& output_id) const override EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet)
    {
        AssertLockHeld(m_wallet.cs_wallet);
        mw::WalletCoin coin;
        if (m_wallet.GetMWEBWalletCoin(output_id, coin)) {
            return coin;
        }
        return std::nullopt;
    }

    mw::Keychain::Ptr GetActiveKeychain() const override
    {
        const std::shared_ptr<MWEB::Wallet>& mweb_wallet = m_wallet.GetMWWallet();
        return mweb_wallet ? mweb_wallet->GetActiveKeychain() : nullptr;
    }

    mw::Keychain::Ptr GetKeychain(const CKeyID& master_scan_key_id) const override
    {
        const std::shared_ptr<MWEB::Wallet>& mweb_wallet = m_wallet.GetMWWallet();
        return mweb_wallet ? mweb_wallet->GetKeychain(master_scan_key_id) : nullptr;
    }

    std::optional<std::string> InferAddressDescriptor(const mw::WalletCoin& coin) const override
    {
        return InferMWEBAddressDescriptor(m_wallet, coin);
    }

private:
    const CWallet& m_wallet;
};

} // namespace

SecretKey GetMWEBRewindKeyForSigning(const CWallet& wallet)
{
    const std::shared_ptr<MWEB::Wallet>& mweb_wallet = wallet.GetMWWallet();
    if (!mweb_wallet) {
        return SecretKey::Random();
    }

    return mweb_wallet->GetRewindKey().value_or(SecretKey::Random());
}

mw::SenderKeyGenerator GetMWEBSenderKeyGeneratorForSigning(const CWallet& wallet)
{
    return [&wallet]() -> util::Result<SecretKey> {
        LOCK(wallet.cs_wallet);
        const std::shared_ptr<MWEB::Wallet>& mweb_wallet = wallet.GetMWWallet();
        if (!mweb_wallet) {
            return SecretKey::Random();
        }

        return mweb_wallet->GenerateSenderKey();
    };
}

TransactionError PSBTFiller::Fill(PartiallySignedTransaction& psbtx, bool& complete, size_t* n_signed)
{
    AssertLockHeld(m_wallet.cs_wallet);

    util::Result<std::unordered_map<mw::Hash, SecretKey>> mweb_spend_keys = PrepareInputs(psbtx);
    if (!mweb_spend_keys) {
        m_wallet.WalletLogPrintf("FillPSBT: %s\n", util::ErrorString(mweb_spend_keys).original);
        return TransactionError::INVALID_PSBT;
    }

    if (const std::optional<util::Error> error = InferMWEBKernelFee(psbtx)) {
        m_wallet.WalletLogPrintf("FillPSBT: %s\n", error->message.original);
        return TransactionError::INVALID_PSBT;
    }

    MWEBSignOutcome mweb_outcome = MWEBSignOutcome::Skipped();
    if (m_opts.sign && psbtx.ContainsMWEBComponents()) {
        const auto count_unsigned_mweb = [&psbtx]() {
            return std::count_if(psbtx.inputs.begin(), psbtx.inputs.end(), [](const PSBTInput& input) {
                return input.IsMWEB() && !input.mweb_sig.has_value();
            });
        };
        const auto unsigned_mweb_before = count_unsigned_mweb();
        const bool missing_mweb_signing_data = std::any_of(psbtx.inputs.begin(), psbtx.inputs.end(), [&mweb_spend_keys](const PSBTInput& input) {
            return input.IsMWEB() && !input.mweb_sig &&
                (!input.mweb_output_id || !input.mweb_amount || !input.mweb_shared_secret || mweb_spend_keys->count(*input.mweb_output_id) == 0);
        });
        if (missing_mweb_signing_data) {
            // Keep updater data in the PSBT, but do not sign script inputs
            // against peg-in placeholders that MWEB signing may later rewrite.
            complete = false;
            return TransactionError::OK;
        }

        util::Result<MWEBSignOutcome> outcome = SignMWEBAndStageCoins(psbtx, *mweb_spend_keys);
        if (!outcome) {
            m_wallet.WalletLogPrintf("FillPSBT: %s\n", util::ErrorString(outcome).original);
            return TransactionError::INVALID_PSBT;
        }
        mweb_outcome = std::move(*outcome);

        // MWEB inputs signed here count toward n_signed just like
        // ScriptPubKeyMan-signed inputs do in the script-signing stage.
        if (n_signed) {
            (*n_signed) += unsigned_mweb_before - count_unsigned_mweb();
        }
    }
    // else: not signing, or no MWEB components — no peg-in script rewrite is
    // possible, so Skipped() is a valid outcome for the script-signing stage.

    TransactionError res = SignScriptInputs(psbtx, mweb_outcome, n_signed);
    if (res != TransactionError::OK) {
        return res;
    }

    RemoveUnnecessaryTransactions(psbtx, m_opts.sighash_type);

    // Complete if every input is now signed
    complete = psbtx.IsComplete();

    return TransactionError::OK;
}

util::Result<std::unordered_map<mw::Hash, SecretKey>> PSBTFiller::PrepareInputs(PartiallySignedTransaction& psbtx)
{
    std::unordered_map<mw::Hash, SecretKey> mweb_spend_keys;
    const WalletMWEBKeyStore mweb_keystore(m_wallet);

    // Get all of the previous transactions
    for (PSBTInput& input : psbtx.inputs) {
        if (PSBTInputSigned(input)) {
            continue;
        }

        // MWEB inputs don't need the previous transaction
        if (input.IsMWEB()) {
            util::Result<std::optional<SecretKey>> spend_key = ResolveMWEBInputKeys(input, mweb_keystore);
            if (!spend_key) {
                return util::Error{util::ErrorString(spend_key)};
            }

            if (spend_key->has_value()) {
                mweb_spend_keys[*input.mweb_output_id] = **spend_key;
            }

            continue;
        }

        // If we have no utxo, grab it from the wallet.
        if (!input.non_witness_utxo) {
            const CWalletTx* prev_tx = m_wallet.FindWalletTx(input.GetID());
            if (prev_tx != nullptr) {
                // We only need the non_witness_utxo, which is a superset of the witness_utxo.
                //   The signing code will switch to the smaller witness_utxo if this is ok.
                input.non_witness_utxo = prev_tx->tx;
            }
        }
    }

    return mweb_spend_keys;
}

std::optional<util::Error> PSBTFiller::InferMWEBKernelFee(PartiallySignedTransaction& psbtx) const
{
    const bool has_mweb_input = std::any_of(psbtx.inputs.begin(), psbtx.inputs.end(), [](const PSBTInput& input) { return input.IsMWEB(); });
    if (!has_mweb_input) {
        return std::nullopt;
    }

    // A missing amount means this PSBT still needs an updater that knows the
    // confidential coin. Do not guess a fee until every input is known.
    if (std::any_of(psbtx.inputs.begin(), psbtx.inputs.end(), [](const PSBTInput& input) {
            return input.IsMWEB() && !input.mweb_amount.has_value();
        })) {
        return std::nullopt;
    }

    // createpsbt rejects mixed-layer inputs, so a draft with only MWEB inputs
    // has exactly one balance equation and its fee is unambiguous. Pre-built
    // mixed transactions already carry their explicit kernel metadata.
    const bool has_transparent_component = std::any_of(psbtx.inputs.begin(), psbtx.inputs.end(), [](const PSBTInput& input) { return !input.IsMWEB(); }) ||
        std::any_of(psbtx.outputs.begin(), psbtx.outputs.end(), [](const PSBTOutput& output) { return !output.IsMWEB(); });
    const bool missing_fee = psbtx.kernels.empty() || std::any_of(psbtx.kernels.begin(), psbtx.kernels.end(), [](const PSBTKernel& kernel) { return !kernel.fee.has_value(); });
    if (has_transparent_component || !missing_fee) {
        return std::nullopt;
    }

    if (psbtx.kernels.size() > 1) {
        return util::Error{Untranslated("Cannot infer MWEB fee across multiple kernels")};
    }

    CAmount input_amount{0};
    for (const PSBTInput& input : psbtx.inputs) {
        if (!input.IsMWEB() || !MoneyRange(*input.mweb_amount) || !MoneyRange(input_amount + *input.mweb_amount)) {
            return util::Error{Untranslated("Invalid MWEB input amount")};
        }
        input_amount += *input.mweb_amount;
    }

    CAmount output_amount{0};
    for (const PSBTOutput& output : psbtx.outputs) {
        if (!output.IsMWEB() || !output.amount || !MoneyRange(*output.amount) || !MoneyRange(output_amount + *output.amount)) {
            return util::Error{Untranslated("Invalid MWEB output amount")};
        }
        output_amount += *output.amount;
    }

    CAmount pegout_amount{0};
    if (!psbtx.kernels.empty()) {
        for (const PegOutCoin& pegout : psbtx.kernels.front().pegouts) {
            if (!MoneyRange(pegout.GetAmount()) || !MoneyRange(pegout_amount + pegout.GetAmount())) {
                return util::Error{Untranslated("Invalid MWEB pegout amount")};
            }
            pegout_amount += pegout.GetAmount();
        }
    }

    const CAmount fee = input_amount - output_amount - pegout_amount;
    if (fee < 0 || !MoneyRange(fee)) {
        return util::Error{Untranslated("MWEB outputs exceed inputs")};
    }

    if (psbtx.kernels.empty()) {
        psbtx.kernels.emplace_back();
    }
    PSBTKernel& kernel = psbtx.kernels.front();
    kernel.fee = fee;
    uint8_t features = mw::Kernel::FEE_FEATURE_BIT;
    features |= kernel.pegin_amount.has_value() ? mw::Kernel::PEGIN_FEATURE_BIT : 0;
    features |= !kernel.pegouts.empty() ? mw::Kernel::PEGOUT_FEATURE_BIT : 0;
    features |= kernel.lock_height.has_value() ? mw::Kernel::HEIGHT_LOCK_FEATURE_BIT : 0;
    features |= kernel.stealth_commit.has_value() ? mw::Kernel::STEALTH_EXCESS_FEATURE_BIT : 0;
    features |= !kernel.extra_data.empty() ? mw::Kernel::EXTRA_DATA_FEATURE_BIT : 0;
    kernel.features = features;
    return std::nullopt;
}

util::Result<MWEBSignOutcome> PSBTFiller::SignMWEBAndStageCoins(PartiallySignedTransaction& psbtx, const std::unordered_map<mw::Hash, SecretKey>& spend_keys)
{
    util::Result<MWEBSignOutcome> outcome = SignPSBTMWEBComponents(psbtx, spend_keys, GetMWEBRewindKeyForSigning(m_wallet), GetMWEBSenderKeyGeneratorForSigning(m_wallet));
    if (!outcome) {
        return util::Error{Untranslated(strprintf("SignPSBTMWEBComponents failed, %s", util::ErrorString(outcome).original))};
    }

    if (!outcome->discovered_coins.empty()) {
        const std::shared_ptr<MWEB::Wallet>& mweb_wallet = m_wallet.GetMWWallet();
        if (!mweb_wallet) {
            return util::Error{Untranslated("MWEB wallet is unavailable for staged MWEB coins")};
        }
        mweb_wallet->StageWalletCoins(outcome->discovered_coins);
    }

    return outcome;
}

TransactionError PSBTFiller::SignScriptInputs(PartiallySignedTransaction& psbtx, const MWEBSignOutcome& /*mweb_outcome*/, size_t* n_signed)
{
    // Build sighash precomputation data only now: the MWEB signing stage,
    // whose outcome this stage requires, may have rewritten peg-in scripts.
    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbtx);

    // Fill in information from ScriptPubKeyMans
    for (ScriptPubKeyMan* spk_man : m_wallet.GetAllScriptPubKeyMans()) {
        int n_signed_this_spkm = 0;
        TransactionError res = spk_man->FillPSBT(psbtx, txdata, m_opts.sighash_type, m_opts.sign, m_opts.bip32derivs, &n_signed_this_spkm, m_opts.finalize);
        if (res != TransactionError::OK) {
            return res;
        }

        if (n_signed) {
            (*n_signed) += n_signed_this_spkm;
        }
    }

    return TransactionError::OK;
}

} // namespace wallet
