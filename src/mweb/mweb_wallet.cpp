#include <mweb/mweb_wallet.h>
#include <mw/crypto/Bulletproofs.h>
#include <mw/crypto/Hasher.h>
#include <mw/models/tx/OutputMask.h>
#include <wallet/coincontrol.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <util/bip32.h>
#include <util/translation.h>

#include <limits>

using namespace MWEB;

namespace {
static constexpr uint64_t SENDER_KEY_LOOKAHEAD = 1000;

void MergeSenderMetadata(mw::Coin& target, const mw::Coin& source)
{
    if (source.sender_key && !target.sender_key) {
        target.sender_key = source.sender_key;
    }
    if (source.shared_secret && !target.shared_secret) {
        target.shared_secret = source.shared_secret;
    }
    if (source.blind && !target.blind) {
        target.blind = source.blind;
    }
    if (source.shared_secret && target.amount == 0) {
        target.amount = source.amount;
    }
    if (source.master_scan_key_id && !target.master_scan_key_id) {
        target.master_scan_key_id = source.master_scan_key_id;
    }
}
}

Wallet::~Wallet() = default;

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
                    m_pWallet->MarkDirty();
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
                coins.push_back(mweb_coin);
            }
        }
    }

    return coins;
}

bool Wallet::RewindOutput(const mw::Output& output, mw::Coin& coin)
{
    coin.Reset();
    mw::Coin sent_coin;
    const bool sent_by_me = RewindOutputSentByMe(output, sent_coin);

    mw::Coin existing_coin;
    if (GetCoin(output.GetOutputID(), existing_coin)) {
        coin = existing_coin;

        if (sent_by_me) {
            MergeSenderMetadata(coin, sent_coin);
            if (coin.HasAddress() && IsChange(*coin.address)) {
                coin.address_index = mw::CHANGE_INDEX;
            }
            const bool external_address = coin.HasAddress() && m_pWallet->IsMine(GenericAddress{*coin.address}) == wallet::ISMINE_NO;
            if (!coin.IsMine() && !external_address) {
                RecoverOwnedOutputFromSenderData(output, coin);
            }
        }

        if (coin.IsMine()) {
            UpgradeCoinSpendKey(coin);
            m_coins[coin.output_id] = coin;
            wallet::WalletBatch(m_pWallet->GetDatabase()).WriteMWEBCoin(coin);
            m_pWallet->MarkDirty();
            return true;
        }

        if (sent_by_me) {
            m_coins[coin.output_id] = coin;
            wallet::WalletBatch(m_pWallet->GetDatabase()).WriteMWEBCoin(coin);
            m_pWallet->MarkDirty();
            return false;
        }
    }

    for (const auto& keychain : GetAllKeychains()) {
        if (keychain->RewindOutput(output, coin)) {
            if (sent_by_me) {
                MergeSenderMetadata(coin, sent_coin);
                UpgradeCoinSpendKey(coin);
            }
            m_coins[coin.output_id] = coin;
            wallet::WalletBatch(m_pWallet->GetDatabase()).WriteMWEBCoin(coin);
            m_pWallet->MarkDirty();
            return true;
        }
    }

    if (sent_by_me) {
        coin = sent_coin;
        if (RecoverOwnedOutputFromSenderData(output, coin)) {
            m_coins[coin.output_id] = coin;
            wallet::WalletBatch(m_pWallet->GetDatabase()).WriteMWEBCoin(coin);
            m_pWallet->MarkDirty();
            return true;
        }

        m_coins[coin.output_id] = coin;
        wallet::WalletBatch(m_pWallet->GetDatabase()).WriteMWEBCoin(coin);
        m_pWallet->MarkDirty();
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

    if (coin.address_index == mw::UNKNOWN_INDEX || coin.address_index == mw::CUSTOM_KEY) {
        return false;
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

void Wallet::StageOutputAddresses(const std::map<mw::Hash, StealthAddress>& addresses_by_output_id)
{
    for (const auto& [output_id, address] : addresses_by_output_id) {
        auto staged_coin = m_staged_coins.find(output_id);
        if (staged_coin != m_staged_coins.end()) {
            staged_coin->second.address = address;
            if (IsChange(address)) {
                staged_coin->second.address_index = mw::CHANGE_INDEX;
            }
        }
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
        m_pWallet->MarkDirty();
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

std::optional<SecretKey> Wallet::GetRewindKey() const
{
    mw::Keychain::Ptr keychain = GetActiveKeychain();
    if (!keychain) {
        return std::nullopt;
    }

    return std::make_optional(keychain->GetRewindKey());
}

util::Result<SecretKey> Wallet::GenerateSenderKey()
{
    LOCK(m_pWallet->cs_wallet);

    mw::Keychain::Ptr keychain = GetActiveKeychain();
    if (!keychain) {
        return SecretKey::Random();
    }

    const CKeyID master_scan_keyid = PublicKey::From(keychain->GetScanSecret()).GetID();
    uint64_t& next_index = m_next_sender_key_indices[master_scan_keyid];
    if (next_index == std::numeric_limits<uint64_t>::max()) {
        return util::Error{Untranslated("MWEB sender key index exhausted")};
    }

    const SecretKey sender_key = keychain->GetSenderKey(next_index);
    const uint64_t next_index_to_write = next_index + 1;
    if (!wallet::WalletBatch(m_pWallet->GetDatabase()).WriteMWEBNextSenderKeyIndex(master_scan_keyid, next_index_to_write)) {
        return util::Error{Untranslated("Failed to write MWEB sender key index")};
    }

    next_index = next_index_to_write;
    return sender_key;
}

void Wallet::LoadNextSenderKeyIndex(const CKeyID& master_scan_keyid, uint64_t next_index)
{
    m_next_sender_key_indices[master_scan_keyid] = next_index;
}

std::optional<Wallet::SenderKeyMatch> Wallet::FindSenderKey(const PublicKey& sender_pubkey)
{
    for (const mw::Keychain::Ptr& keychain : GetAllKeychains()) {
        const CKeyID master_scan_keyid = PublicKey::From(keychain->GetScanSecret()).GetID();
        const uint64_t next_index = m_next_sender_key_indices[master_scan_keyid];
        // Include recently issued keys so outputs from the transaction currently
        // being committed can be recognized after GenerateSenderKey advances.
        const uint64_t scan_begin = next_index > SENDER_KEY_LOOKAHEAD ? next_index - SENDER_KEY_LOOKAHEAD : 0;
        const uint64_t scan_end = next_index > std::numeric_limits<uint64_t>::max() - SENDER_KEY_LOOKAHEAD
            ? std::numeric_limits<uint64_t>::max()
            : next_index + SENDER_KEY_LOOKAHEAD;

        for (uint64_t index = scan_begin; index < scan_end; ++index) {
            const SecretKey sender_key = keychain->GetSenderKey(index);
            if (PublicKey::From(sender_key) == sender_pubkey) {
                return SenderKeyMatch{
                    keychain,
                    master_scan_keyid,
                    index,
                    sender_key
                };
            }
        }

    }

    return std::nullopt;
}

bool Wallet::AdvanceNextSenderKeyIndex(const CKeyID& master_scan_keyid, uint64_t sender_key_index)
{
    uint64_t& next_index = m_next_sender_key_indices[master_scan_keyid];
    if (sender_key_index < next_index) {
        return true;
    }

    if (sender_key_index == std::numeric_limits<uint64_t>::max()) {
        return false;
    }

    const uint64_t next_index_to_write = sender_key_index + 1;
    if (!wallet::WalletBatch(m_pWallet->GetDatabase()).WriteMWEBNextSenderKeyIndex(master_scan_keyid, next_index_to_write)) {
        return false;
    }

    next_index = next_index_to_write;
    return true;
}

bool Wallet::RewindOutputSentByMe(const mw::Output& output, mw::Coin& coin)
{
    const std::optional<SenderKeyMatch> match = FindSenderKey(output.GetSenderPubKey());
    if (!match) {
        return false;
    }

    if (!AdvanceNextSenderKeyIndex(match->master_scan_keyid, match->index)) {
        return false;
    }

    coin.Reset();
    coin.output_id = output.GetOutputID();
    coin.sender_key = match->sender_key;
    coin.master_scan_key_id = match->master_scan_keyid;

    if (output.HasStandardFields()) {
        const SecretKey proof_nonce = Hasher(EHashTag::PROOF_NONCE)
            .Append(match->keychain->GetRewindKey())
            .Append(output.GetCommitment())
            .hash();
        const BigInt<32> proof_message = Bulletproofs::Rewind(
            output.GetCommitment(),
            *output.GetRangeProof(),
            output.GetOutputMessage().Serialized(),
            proof_nonce
        );

        if (!proof_message.IsZero()) {
            const SecretKey shared_secret(proof_message.data());
            const OutputMask mask = OutputMask::FromShared(shared_secret);
            const uint64_t value = mask.MaskValue(output.GetMaskedValue());

            if (value <= static_cast<uint64_t>(MAX_MONEY) && MoneyRange(static_cast<CAmount>(value)) && mask.SwitchCommit(value) == output.GetCommitment()) {
                coin.amount = static_cast<CAmount>(value);
                coin.blind = mask.GetRawBlind();
                coin.shared_secret = shared_secret;
            }
        }
    }

    return true;
}

bool Wallet::RecoverOwnedOutputFromSenderData(const mw::Output& output, mw::Coin& coin) const
{
    if (!coin.HasSharedSecret()) {
        return false;
    }

    const PublicKey subaddress_spend_pubkey = output.GetReceiverPubKey().Div(Hashed(EHashTag::OUT_KEY, *coin.shared_secret));
    for (const mw::Keychain::Ptr& keychain : GetAllKeychains()) {
        if (!keychain || !keychain->HasSpendPubKey()) {
            continue;
        }

        const StealthAddress address(subaddress_spend_pubkey.Mul(keychain->GetScanSecret()), subaddress_spend_pubkey);
        std::optional<uint32_t> address_index = keychain->LookupAddressIndex(address);

        if (!address_index.has_value()) {
            continue;
        }
        if (m_pWallet->IsMine(GenericAddress{address}) == wallet::ISMINE_NO) {
            continue;
        }

        coin.output_id = output.GetOutputID();
        coin.address = address;
        coin.address_index = *address_index;
        coin.master_scan_key_id = PublicKey::From(keychain->GetScanSecret()).GetID();
        UpgradeCoinSpendKey(coin);
        return true;
    }

    return false;
}

bool Wallet::UpgradeCoinSpendKey(mw::Coin& coin) const
{
    if (coin.HasSpendKey()) {
        return true;
    }
    if (!coin.IsMine()) {
        return false;
    }

    if (coin.master_scan_key_id.has_value()) {
        const mw::Keychain::Ptr keychain = GetKeychain(*coin.master_scan_key_id);
        if (keychain) {
            coin.spend_key = keychain->CalculateOutputSpendKey(coin);
            if (coin.HasSpendKey()) {
                return true;
            }
        }
    }

    for (const mw::Keychain::Ptr& keychain : GetAllKeychains()) {
        if (!keychain) {
            continue;
        }

        coin.spend_key = keychain->CalculateOutputSpendKey(coin);
        if (coin.HasSpendKey()) {
            coin.master_scan_key_id = PublicKey::From(keychain->GetScanSecret()).GetID();
            return true;
        }
    }

    return false;
}
