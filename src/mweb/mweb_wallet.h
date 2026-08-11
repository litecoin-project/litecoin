#pragma once

#include <consensus/amount.h>
#include <key.h>
#include <mw/models/block/Block.h>
#include <mw/models/tx/Transaction.h>
#include <mw/models/wallet/WalletCoin.h>
#include <mw/models/wallet/StealthAddress.h>
#include <mw/wallet/Keychain.h>
#include <streams.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <wallet/wallet.h>
#include <cstdint>
#include <optional>
#include <variant>
#include <map>
#include <set>
#include <vector>

namespace MWEB {

class Wallet
{
    struct SenderKeyMatch
    {
        mw::Keychain::Ptr keychain;
        CKeyID master_scan_keyid;
        uint64_t index;
        SecretKey sender_key;
    };

    wallet::CWallet* m_pWallet;

    // All state below is guarded by m_pWallet->cs_wallet, enforced by the
    // EXCLUSIVE_LOCKS_REQUIRED annotations on the methods.
    std::map<mw::Hash, mw::WalletCoin> m_coins;
    std::map<mw::Hash, mw::WalletCoin> m_staged_coins;
    std::map<CKeyID, uint64_t> m_next_sender_key_indices;

public:
    Wallet(wallet::CWallet* pWallet)
        : m_pWallet(pWallet) {}
    ~Wallet();

    bool IsChange(const StealthAddress& address) const;
    bool GetWalletCoin(const mw::Hash& output_id, mw::WalletCoin& coin) const EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet);

    // Loops through the transactions in the wallet and attempts to fill
    // in missing information for mw::WalletCoin's, in particular the spend key.
    // Intended to be called after unlocking an encrypted wallet.
    void UpgradeCoins() EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet);

    std::vector<mw::WalletCoin> RewindOutputs(const CTransaction& tx) EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet);
    bool RewindOutput(const mw::Output& output, mw::WalletCoin& coin) EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet);

    // Derives the stealth address for a given coin using the keychain the coin came from.
    bool GetStealthAddress(const mw::WalletCoin& coin, StealthAddress& address) const;

    // Derives the stealth address for a given index using the active MWEB keychain.
    bool GetStealthAddress(const uint32_t index, StealthAddress& address) const;

    void LoadToWallet(const mw::WalletCoin& coin) EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet);
    bool SaveToWallet(const std::vector<mw::WalletCoin>& coins) EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet);
    void StageWalletCoins(const std::map<mw::Hash, mw::WalletCoin>& wallet_coins_by_output_id) EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet);
    void StageOutputAddresses(const std::map<mw::Hash, StealthAddress>& addresses_by_output_id) EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet);
    bool SaveStagedCoinsToWallet(const std::set<mw::Hash>& output_ids) EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet);

    mw::Keychain::Ptr GetKeychain(const CKeyID& master_scan_keyid) const;
    std::optional<SecretKey> GetRewindKey() const;
    util::Result<SecretKey> GenerateSenderKey() EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet);
    void LoadNextSenderKeyIndex(const CKeyID& master_scan_keyid, uint64_t next_index) EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet);

private:
    // Persists a coin after raising the wallet's minversion to FEATURE_V24.
    // In-memory state is updated only after the database write succeeds.
    bool SaveCoin(const mw::WalletCoin& coin) EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet);

    std::vector<mw::Keychain::Ptr> GetAllKeychains() const;
    mw::Keychain::Ptr GetActiveKeychain() const;

    std::optional<SenderKeyMatch> FindSenderKey(const PublicKey& sender_pubkey) EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet);
    bool AdvanceNextSenderKeyIndex(const CKeyID& master_scan_keyid, uint64_t sender_key_index) EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet);
    bool RewindOutputSentByMe(const mw::Output& output, mw::WalletCoin& coin) EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet);
    bool RecoverOwnedOutputFromSenderData(const mw::Output& output, mw::WalletCoin& coin) const EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet);
    bool UpgradeWalletCoinSpendKey(mw::WalletCoin& coin) const;

    void UpgradeCoins(const mw::Keychain::Ptr& keychain) EXCLUSIVE_LOCKS_REQUIRED(m_pWallet->cs_wallet);
};

} // namespace MWEB
