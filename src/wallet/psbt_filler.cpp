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

    MWEBSignOutcome mweb_outcome = MWEBSignOutcome::Skipped();
    if (m_opts.sign && psbtx.ContainsMWEBComponents()) {
        const auto count_unsigned_mweb = [&psbtx]() {
            return std::count_if(psbtx.inputs.begin(), psbtx.inputs.end(), [](const PSBTInput& input) {
                return input.IsMWEB() && !input.mweb_sig.has_value();
            });
        };
        const auto unsigned_mweb_before = count_unsigned_mweb();
        const bool missing_mweb_spend_key = std::any_of(psbtx.inputs.begin(), psbtx.inputs.end(), [&mweb_spend_keys](const PSBTInput& input) {
            return input.IsMWEB() && !input.mweb_sig && (!input.mweb_output_id || mweb_spend_keys->count(*input.mweb_output_id) == 0);
        });
        if (missing_mweb_spend_key) {
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
