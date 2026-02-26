#pragma once

#include <consensus/amount.h>
#include <key.h>
#include <mw/models/block/Block.h>
#include <mw/models/tx/Transaction.h>
#include <mw/models/wallet/Coin.h>
#include <mw/models/wallet/StealthAddress.h>
#include <mw/wallet/Keychain.h>
#include <streams.h>
#include <util/strencodings.h>
#include <optional>
#include <variant>
#include <map>
#include <set>

namespace wallet {
class CWallet;
}

namespace MWEB {

class Wallet
{
    wallet::CWallet* m_pWallet;
    std::map<mw::Hash, mw::Coin> m_coins;

public:
    Wallet(wallet::CWallet* pWallet)
        : m_pWallet(pWallet) {}

    bool IsChange(const StealthAddress& address) const;
    bool GetCoin(const mw::Hash& output_id, mw::Coin& coin) const;

    // Loops through the transactions in the wallet and attempts to fill
    // in missing information for mw::Coin's, in particular the spend key.
    // Intended to be called after unlocking an encrypted wallet.
    void UpgradeCoins();

    std::vector<mw::Coin> RewindOutputs(const CTransaction& tx);
    bool RewindOutput(const mw::Output& output, mw::Coin& coin);

    // Derives the stealth address for a given coin using the keychain the coin came from.
    bool GetStealthAddress(const mw::Coin& coin, StealthAddress& address) const;

    // Derives the stealth address for a given index using the active MWEB keychain.
    bool GetStealthAddress(const uint32_t index, StealthAddress& address) const;

    void LoadToWallet(const mw::Coin& coin);
    void SaveToWallet(const std::vector<mw::Coin>& coins);
    
    mw::Keychain::Ptr GetKeychain(const CKeyID& master_scan_keyid) const;

private:
    std::vector<mw::Keychain::Ptr> GetAllKeychains() const;
    mw::Keychain::Ptr GetActiveKeychain() const;

    void UpgradeCoins(const mw::Keychain::Ptr& keychain);
};

struct WalletTxInfo
{
    // When connecting a block, if an output is found that belongs to us,
    // we check if we have a CWalletTx that created it.
    // If none is found, then we assume it is a newly received coin,
    // so we create an empty transaction and store the received coin here.
    std::optional<mw::Coin> received_coin;

    // When connecting a block, if one of the wallet's coins is spent,
    // we check if we have a CWalletTx that spent it.
    // If none is found, then we assume it was spent by another wallet,
    // so we create an empty Transaction and store the spent hash here.
    std::optional<mw::Hash> spent_input;

    uint256 m_hash;

    WalletTxInfo()
        : received_coin(std::nullopt), spent_input(std::nullopt) { }
    WalletTxInfo(mw::Coin received)
        : received_coin(std::move(received)), spent_input(std::nullopt), m_hash(CalcHash()) {}
    WalletTxInfo(mw::Hash spent)
        : received_coin(std::nullopt), spent_input(std::move(spent)), m_hash(CalcHash()) {}

    bool operator==(const WalletTxInfo& rhs) const noexcept
    {
        return received_coin == rhs.received_coin && spent_input == rhs.spent_input;
    }

    SERIALIZE_METHODS(WalletTxInfo, obj)
    {
        bool received = !!obj.received_coin;
        READWRITE(received);

        if (received) {
            mw::Coin coin;
            SER_WRITE(obj, coin = *obj.received_coin);
            READWRITE(coin);
            SER_READ(obj, obj.received_coin = std::make_optional<mw::Coin>(std::move(coin)));
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
        if (!!received_coin) {
            return uint256(Hasher().Append<int8_t>('R').Append(received_coin->output_id).hash().vec());
        } else {
            return uint256(Hasher().Append<int8_t>('S').Append(*spent_input).hash().vec());
        }
    }
};

} // namespace MWEB
