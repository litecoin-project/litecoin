#include <mweb/mweb_wallet.h>
#include <wallet/wallet.h>
#include <wallet/coincontrol.h>
#include <util/bip32.h>

using namespace MWEB;

void Wallet::UpgradeCoins()
{
    std::vector<mw::Keychain::Ptr> keychains = GetAllKeychains();
    for (const auto& keychain : keychains) {
        if (keychain->HasSpendSecret()) {
            UpgradeCoins(keychain);
        }
    }
}

void Wallet::UpgradeCoins(const mw::Keychain::Ptr& keychain)
{
    // Loop through transactions and try upgrading output coins
    for (auto& entry : m_pWallet->mapWallet) {
        wallet::CWalletTx* wtx = &entry.second;
        RewindOutputs(*wtx->tx);

        if (wtx->mweb_wtx_info && wtx->mweb_wtx_info->received_coin) {
            mw::Coin& coin = *wtx->mweb_wtx_info->received_coin;
            if (!coin.HasSpendKey()) {
                coin.spend_key = keychain->CalculateOutputSpendKey(coin);

                // If spend key was populated, update the database and m_coins map.
                if (coin.HasSpendKey()) {
                    m_coins[coin.output_id] = coin;

                    wallet::WalletBatch batch(m_pWallet->GetDatabase());
                    batch.WriteMWEBCoin(coin);
                    batch.WriteTx(*wtx);
                }
            }
        }
    }
}

std::vector<mw::Coin> Wallet::RewindOutputs(const CTransaction& tx)
{
    std::vector<mw::Coin> coins;

    if (tx.HasMWEBTx()) {
        for (const mw::Output& output : tx.mweb_tx.m_transaction->GetOutputs()) {
            mw::Coin mweb_coin;
            if (RewindOutput(output, mweb_coin)) {
                LogPrintf("DEBUG: Rewound output: %s\n", mweb_coin.output_id.ToHex());
                coins.push_back(mweb_coin);
            }
        }
    }

    return coins;
}

bool Wallet::RewindOutput(const mw::Output& output, mw::Coin& coin)
{
    if (GetCoin(output.GetOutputID(), coin) && coin.IsMine()) {
        // If the coin has the spend key, it's fully rewound.
        // If not, try rewinding further if we have the master spend key (i.e. wallet is unlocked).
        if (coin.HasSpendKey()) {
            return true;
        }

        if (coin.master_scan_key_id.has_value()) {
            // If the coin has a master scan key ID, try to get the keychain from it.
            // This is used for coins that were created before the wallet was unlocked.
            mw::Keychain::Ptr keychain = GetKeychain(coin.master_scan_key_id.value());
            if (!keychain || !keychain->HasSpendSecret()) {
                return true;
            }
        }
    }

    for (const auto& keychain : GetAllKeychains()) {
        if (keychain->RewindOutput(output, coin)) {
            m_coins[coin.output_id] = coin;
            wallet::WalletBatch(m_pWallet->GetDatabase()).WriteMWEBCoin(coin);
            return true;
        }
    }

    return false;
}

bool Wallet::IsChange(const StealthAddress& address) const
{
    for (const auto& keychain : GetAllKeychains()) {
        if (keychain && keychain->HasSpendPubKey()) {
            StealthAddress change_addr = keychain->GetStealthAddress(mw::CHANGE_INDEX);
            if (change_addr == address) {
                return true;
            }
        }
    }
    return false;
}

bool Wallet::GetStealthAddress(const mw::Coin& coin, StealthAddress& address) const
{
    if (coin.HasAddress()) {
        address = *coin.address;
        return true;
    }

    if (coin.master_scan_key_id.has_value()) {
        mw::Keychain::Ptr keychain = GetKeychain(coin.master_scan_key_id.value());
        if (keychain && keychain->HasSpendPubKey()) {
            address = keychain->GetStealthAddress(coin.address_index);
            return true;
        }

        return false;
    }

    return GetStealthAddress(coin.address_index, address);
}

bool Wallet::GetStealthAddress(const uint32_t index, StealthAddress& address) const
{
    mw::Keychain::Ptr keychain = GetActiveKeychain();
    if (!keychain || index == mw::UNKNOWN_INDEX || index == mw::CUSTOM_KEY) {
        return false;
    }

    if (!keychain->HasSpendPubKey()) {
        return false;
    }

    address = keychain->GetStealthAddress(index);
    return true;
}

void Wallet::LoadToWallet(const mw::Coin& coin)
{
    m_coins[coin.output_id] = coin;
}

void Wallet::SaveToWallet(const std::vector<mw::Coin>& coins)
{
    wallet::WalletBatch batch(m_pWallet->GetDatabase());
    for (const mw::Coin& coin : coins) {
        m_coins[coin.output_id] = coin;
        batch.WriteMWEBCoin(coin);
    }
}

void Wallet::StageCoins(const std::map<mw::Hash, mw::Coin>& coins_by_output_id)
{
    for (const auto& [output_id, coin] : coins_by_output_id) {
        m_staged_coins[output_id] = coin;
    }
}

void Wallet::SaveStagedCoinsToWallet(const std::set<mw::Hash>& output_ids)
{
    wallet::WalletBatch batch(m_pWallet->GetDatabase());
    for (const mw::Hash& output_id : output_ids) {
        auto iter = m_staged_coins.find(output_id);
        if (iter == m_staged_coins.end()) {
            continue;
        }

        m_coins[output_id] = iter->second;
        batch.WriteMWEBCoin(iter->second);
        m_staged_coins.erase(iter);
    }
}

bool Wallet::GetCoin(const mw::Hash& output_id, mw::Coin& coin) const
{
    auto iter = m_coins.find(output_id);
    if (iter != m_coins.end()) {
        coin = iter->second;
        return true;
    }

    coin.Reset();
    return false;
}

mw::Keychain::Ptr Wallet::GetActiveKeychain() const
{
    auto spk_man = m_pWallet->GetScriptPubKeyMan(OutputType::MWEB, false);
    if (spk_man && spk_man->GetMWEBKeychain()) {
        return spk_man->GetMWEBKeychain();
    }
    return nullptr;
}

std::vector<mw::Keychain::Ptr> Wallet::GetAllKeychains() const
{
    std::vector<mw::Keychain::Ptr> keychains;
    auto spk_mans = m_pWallet->GetAllScriptPubKeyMans();
    for (const auto& spk_man : spk_mans) {
        auto keychain = spk_man->GetMWEBKeychain();
        if (keychain) {
            keychains.push_back(keychain);
        }
    }
    return keychains;
}

mw::Keychain::Ptr Wallet::GetKeychain(const CKeyID& master_scan_keyid) const
{
    for (const auto& keychain : GetAllKeychains()) {
        if (PublicKey::From(keychain->GetScanSecret()).GetID() == master_scan_keyid) {
            return keychain;
        }
    }
    return nullptr;
}
