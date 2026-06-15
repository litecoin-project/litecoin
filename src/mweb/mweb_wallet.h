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
#include <cstdint>
#include <optional>
#include <variant>
#include <map>
#include <set>
#include <vector>

namespace wallet {
class CWallet;
}

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
    std::map<mw::Hash, mw::WalletCoin> m_coins;
    std::map<mw::Hash, mw::WalletCoin> m_staged_coins;
    std::map<CKeyID, uint64_t> m_next_sender_key_indices;

public:
    Wallet(wallet::CWallet* pWallet)
        : m_pWallet(pWallet) {}
    ~Wallet();

    bool IsChange(const StealthAddress& address) const;
    bool GetWalletCoin(const mw::Hash& output_id, mw::WalletCoin& coin) const;

    // Loops through the transactions in the wallet and attempts to fill
    // in missing information for mw::WalletCoin's, in particular the spend key.
    // Intended to be called after unlocking an encrypted wallet.
    void UpgradeCoins();

    std::vector<mw::WalletCoin> RewindOutputs(const CTransaction& tx);
    bool RewindOutput(const mw::Output& output, mw::WalletCoin& coin);

    // Derives the stealth address for a given coin using the keychain the coin came from.
    bool GetStealthAddress(const mw::WalletCoin& coin, StealthAddress& address) const;

    // Derives the stealth address for a given index using the active MWEB keychain.
    bool GetStealthAddress(const uint32_t index, StealthAddress& address) const;

    void LoadToWallet(const mw::WalletCoin& coin);
    void SaveToWallet(const std::vector<mw::WalletCoin>& coins);
    void StageWalletCoins(const std::map<mw::Hash, mw::WalletCoin>& wallet_coins_by_output_id);
    void StageOutputAddresses(const std::map<mw::Hash, StealthAddress>& addresses_by_output_id);
    void SaveStagedCoinsToWallet(const std::set<mw::Hash>& output_ids);
    
    mw::Keychain::Ptr GetKeychain(const CKeyID& master_scan_keyid) const;
    std::optional<SecretKey> GetRewindKey() const;
    util::Result<SecretKey> GenerateSenderKey();
    void LoadNextSenderKeyIndex(const CKeyID& master_scan_keyid, uint64_t next_index);

private:
    std::vector<mw::Keychain::Ptr> GetAllKeychains() const;
    mw::Keychain::Ptr GetActiveKeychain() const;

    std::optional<SenderKeyMatch> FindSenderKey(const PublicKey& sender_pubkey);
    bool AdvanceNextSenderKeyIndex(const CKeyID& master_scan_keyid, uint64_t sender_key_index);
    bool RewindOutputSentByMe(const mw::Output& output, mw::WalletCoin& coin);
    bool RecoverOwnedOutputFromSenderData(const mw::Output& output, mw::WalletCoin& coin) const;
    bool UpgradeWalletCoinSpendKey(mw::WalletCoin& coin) const;

    void UpgradeCoins(const mw::Keychain::Ptr& keychain);
};

struct WalletTxInfo
{
    // When connecting a block, if an output is found that belongs to us,
    // we check if we have a CWalletTx that created it.
    // If none is found, then we assume it is a newly received coin,
    // so we create an empty transaction and store the received coin here.
    std::optional<mw::WalletCoin> received_wallet_coin;

    // When connecting a block, if one of the wallet's coins is spent,
    // we check if we have a CWalletTx that spent it.
    // If none is found, then we assume it was spent by another wallet,
    // so we create an empty Transaction and store the spent hash here.
    std::optional<mw::Hash> spent_input;

    uint256 m_hash;

    WalletTxInfo()
        : received_wallet_coin(std::nullopt), spent_input(std::nullopt) { }
    WalletTxInfo(mw::WalletCoin received)
        : received_wallet_coin(std::move(received)), spent_input(std::nullopt), m_hash(CalcHash()) {}
    WalletTxInfo(mw::Hash spent)
        : received_wallet_coin(std::nullopt), spent_input(std::move(spent)), m_hash(CalcHash()) {}

    bool operator==(const WalletTxInfo& rhs) const noexcept
    {
        return received_wallet_coin == rhs.received_wallet_coin && spent_input == rhs.spent_input;
    }

    SERIALIZE_METHODS(WalletTxInfo, obj)
    {
        bool received = !!obj.received_wallet_coin;
        READWRITE(received);

        if (received) {
            mw::WalletCoin coin;
            SER_WRITE(obj, coin = *obj.received_wallet_coin);
            READWRITE(coin);
            SER_READ(obj, obj.received_wallet_coin = std::make_optional<mw::WalletCoin>(std::move(coin)));
        } else {
            mw::Hash output_id;
            SER_WRITE(obj, output_id = *obj.spent_input);
            READWRITE(output_id);
            SER_READ(obj, obj.spent_input = std::make_optional<mw::Hash>(std::move(output_id)));
        }

        SER_READ(obj, obj.m_hash = obj.CalcHash());
    }

    static WalletTxInfo FromHex(const std::string& str)
    {
        CDataStream stream(MakeByteSpan(ParseHex(str)), SER_DISK, PROTOCOL_VERSION);

        WalletTxInfo wtx_info;
        stream >> wtx_info;
        return wtx_info;
    }

    std::string ToHex() const
    {
        CDataStream stream(SER_DISK, PROTOCOL_VERSION);
        stream << *this;
        return HexStr(Span<std::byte>(stream.data(), stream.size()));
    }

    const uint256& GetHash() const {
        return m_hash;
    }

private:
    uint256 CalcHash() const {
        if (!!received_wallet_coin) {
            return uint256(Hasher().Append<int8_t>('R').Append(received_wallet_coin->output_id).hash().vec());
        } else {
            return uint256(Hasher().Append<int8_t>('S').Append(*spent_input).hash().vec());
        }
    }
};

} // namespace MWEB
