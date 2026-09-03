// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PSBT_FILLER_H
#define BITCOIN_WALLET_PSBT_FILLER_H

#include <psbt.h>
#include <wallet/mweb_psbt.h>
#include <wallet/wallet.h>

namespace wallet {

/**
 * Orchestrates filling and signing a PSBT with a wallet's keys, as a sequence
 * of explicit stages:
 *
 *  1. PrepareInputs      — the Updater role. Attaches previous transactions to
 *                          script inputs, resolves MWEB input metadata, and
 *                          infers the fee for unambiguous MWEB-only drafts.
 *                          Runs regardless of Options::sign.
 *  2. SignMWEBAndStageCoins — signs the MWEB components and stages discovered
 *                          wallet coins. Only runs when signing a PSBT with
 *                          MWEB components. May rewrite peg-in scripts.
 *  3. SignScriptInputs   — signs the canonical-side inputs via each
 *                          ScriptPubKeyMan. Builds sighash precomputation data
 *                          itself, and requires the MWEBSignOutcome from stage
 *                          2, so it cannot run against stale peg-in scripts.
 */
class PSBTFiller
{
public:
    struct Options {
        int sighash_type;
        bool sign;
        bool bip32derivs;
        bool finalize;
    };

    PSBTFiller(const CWallet& wallet, Options options) : m_wallet(wallet), m_opts(options) {}

    TransactionError Fill(PartiallySignedTransaction& psbtx, bool& complete, size_t* n_signed) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet);

private:
    util::Result<std::unordered_map<mw::Hash, SecretKey>> PrepareInputs(PartiallySignedTransaction& psbtx) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet);
    std::optional<util::Error> InferMWEBKernelFee(PartiallySignedTransaction& psbtx) const;
    util::Result<MWEBSignOutcome> SignMWEBAndStageCoins(PartiallySignedTransaction& psbtx, const std::unordered_map<mw::Hash, SecretKey>& spend_keys) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet);
    TransactionError SignScriptInputs(PartiallySignedTransaction& psbtx, const MWEBSignOutcome& mweb_outcome, size_t* n_signed) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet);

    const CWallet& m_wallet;
    const Options m_opts;
};

//! Rewind key used when signing on behalf of the wallet; random if unavailable.
SecretKey GetMWEBRewindKeyForSigning(const CWallet& wallet);

//! Sender-key source used when signing on behalf of the wallet.
mw::SenderKeyGenerator GetMWEBSenderKeyGeneratorForSigning(const CWallet& wallet);

} // namespace wallet

#endif // BITCOIN_WALLET_PSBT_FILLER_H
