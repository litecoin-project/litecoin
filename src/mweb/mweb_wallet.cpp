#include <mweb/mweb_wallet.h>
#include <mw/crypto/Bulletproofs.h>
#include <mw/crypto/Hasher.h>
#include <mw/crypto/KeyDerivation.h>
#include <mw/models/tx/OutputMask.h>
#include <wallet/coincontrol.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <util/bip32.h>
#include <util/system.h>
#include <util/translation.h>

#include <limits>

using namespace MWEB;

namespace {
void MergeSenderMetadata(mw::WalletCoin& target, const mw::WalletCoin& source)
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

std::optional<SecretKey> DeriveSharedSecret(const mw::WalletCoin& coin, const StealthAddress& address)
{
    if (!coin.sender_key || coin.amount < 0 || !MoneyRange(coin.amount)) {
        return std::nullopt;
    }

    return mw::DeriveSharedSecret(*coin.sender_key, address, coin.amount);
}
}

Wallet::~Wallet() = default;

void Wallet::UpgradeCoins()
{
    AssertLockHeld(m_pWallet->cs_wallet);

    const std::vector<mw::Keychain::Ptr> keychains = GetAllKeychains();
    if (keychains.empty()) {
        return;
    }

    // Retry full wallet transactions after keychains are loaded or refreshed
    // so outputs missed during record loading can be recovered. Rewinding only
    // requires scan capability; output spend keys are derived only for signing.
    for (const auto& entry : m_pWallet->mapWallet) {
        RewindOutputs(*entry.second.tx);
    }
}

void Wallet::RewindOutputs(const CTransaction& tx)
{
    AssertLockHeld(m_pWallet->cs_wallet);

    if (tx.HasMWEBTx()) {
        for (const mw::Output& output : tx.mweb_tx.m_transaction->GetOutputs()) {
            RewindOutput(output);
        }
    }
}

bool Wallet::RewindOutput(const mw::Output& output)
{
    AssertLockHeld(m_pWallet->cs_wallet);
    mw::WalletCoin coin;
    coin.Reset();
    mw::WalletCoin sent_coin;
    const bool sent_by_me = RewindOutputSentByMe(output, sent_coin);

    mw::WalletCoin existing_coin;
    if (GetWalletCoin(output.GetOutputID(), existing_coin)) {
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
            return SaveCoin(coin);
        }

        if (sent_by_me) {
            (void)SaveCoin(coin);
            return false;
        }
    }

    for (const auto& keychain : GetAllKeychains()) {
        if (keychain->RewindOutput(output, coin)) {
            if (sent_by_me) {
                MergeSenderMetadata(coin, sent_coin);
            }
            return SaveCoin(coin);
        }
    }

    if (sent_by_me) {
        coin = sent_coin;
        if (RecoverOwnedOutputFromSenderData(output, coin)) {
            return SaveCoin(coin);
        }

        (void)SaveCoin(coin);
    }

    return false;
}

bool Wallet::SaveCoin(const mw::WalletCoin& coin)
{
    AssertLockHeld(m_pWallet->cs_wallet);
    wallet::WalletBatch batch(m_pWallet->GetDatabase());

    // WalletCoin v4 is intentionally unreadable by released pre-v24 versions.
    if (!m_pWallet->SetMinVersion(wallet::FEATURE_V24, &batch)) {
        m_pWallet->WalletLogPrintf("Failed to write wallet minimum version before saving MWEB coin %s\n", coin.output_id.ToHex());
        return false;
    }

    if (!batch.WriteMWEBWalletCoin(coin)) {
        m_pWallet->WalletLogPrintf("Failed to write MWEB coin %s\n", coin.output_id.ToHex());
        return false;
    }

    m_coins[coin.output_id] = coin;
    m_pWallet->MarkDirty();
    return true;
}

bool Wallet::IsChange(const StealthAddress& address) const
{
    for (const auto& keychain : GetAllKeychains()) {
        if (keychain && keychain->HasSpendPubKey()) {
            StealthAddress change_addr = keychain->DeriveAddress(mw::CHANGE_INDEX);
            if (change_addr == address) {
                return true;
            }
        }
    }
    return false;
}

bool Wallet::GetStealthAddress(const mw::WalletCoin& coin, StealthAddress& address) const
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
            address = keychain->DeriveAddress(coin.address_index);
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

    address = keychain->DeriveAddress(index);
    return true;
}

bool Wallet::SetActiveMasterScanKeyId(mw::WalletCoin& coin) const
{
    AssertLockHeld(m_pWallet->cs_wallet);
    if (coin.master_scan_key_id || !coin.address) {
        return false;
    }

    const mw::Keychain::Ptr keychain = GetActiveKeychain();
    if (!keychain || coin.address->GetSpendPubKey().Mul(keychain->GetScanSecret()) != coin.address->GetScanPubKey()) {
        return false;
    }

    coin.master_scan_key_id = PublicKey::From(keychain->GetScanSecret()).GetID();
    return true;
}

void Wallet::LoadToWallet(const mw::WalletCoin& coin)
{
    AssertLockHeld(m_pWallet->cs_wallet);
    m_coins[coin.output_id] = coin;
}

bool Wallet::SaveToWallet(const std::vector<mw::WalletCoin>& coins)
{
    AssertLockHeld(m_pWallet->cs_wallet);
    for (const mw::WalletCoin& coin : coins) {
        if (!SaveCoin(coin)) {
            return false;
        }
    }
    return true;
}

void Wallet::StageWalletCoins(const std::map<mw::Hash, mw::WalletCoin>& wallet_coins_by_output_id)
{
    AssertLockHeld(m_pWallet->cs_wallet);
    for (const auto& [output_id, coin] : wallet_coins_by_output_id) {
        m_staged_coins[output_id] = coin;
    }
}

void Wallet::StageOutputAddresses(const std::map<mw::Hash, StealthAddress>& addresses_by_output_id)
{
    AssertLockHeld(m_pWallet->cs_wallet);
    for (const auto& [output_id, address] : addresses_by_output_id) {
        auto staged_coin = m_staged_coins.find(output_id);
        if (staged_coin != m_staged_coins.end()) {
            mw::WalletCoin& coin = staged_coin->second;
            coin.address = address;
            if (IsChange(address)) {
                coin.address_index = mw::CHANGE_INDEX;
            } else if (coin.address_index == mw::UNKNOWN_INDEX && m_pWallet->IsMine(GenericAddress{address}) != wallet::ISMINE_NO) {
                for (const mw::Keychain::Ptr& keychain : GetAllKeychains()) {
                    if (!keychain || !keychain->HasSpendPubKey()) {
                        continue;
                    }

                    std::optional<uint32_t> address_index = keychain->LookupAddressIndex(address);
                    if (address_index.has_value()) {
                        coin.address_index = *address_index;
                        coin.master_scan_key_id = PublicKey::From(keychain->GetScanSecret()).GetID();
                        break;
                    }
                }
            }

            if (coin.IsMine()) {
                if (!coin.shared_secret) {
                    coin.shared_secret = DeriveSharedSecret(coin, address);
                }
            }
        }
    }
}

bool Wallet::SaveStagedCoinsToWallet(const std::set<mw::Hash>& output_ids)
{
    AssertLockHeld(m_pWallet->cs_wallet);
    for (const mw::Hash& output_id : output_ids) {
        auto iter = m_staged_coins.find(output_id);
        if (iter == m_staged_coins.end()) {
            continue;
        }

        if (!SaveCoin(iter->second)) {
            return false;
        }
        m_staged_coins.erase(iter);
    }
    return true;
}

bool Wallet::GetWalletCoin(const mw::Hash& output_id, mw::WalletCoin& coin) const
{
    AssertLockHeld(m_pWallet->cs_wallet);
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
        const auto& keychain = spk_man->GetMWEBKeychain();
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
    AssertLockHeld(m_pWallet->cs_wallet);

    mw::Keychain::Ptr keychain = GetActiveKeychain();
    if (!keychain) {
        return SecretKey::Random();
    }

    const CKeyID master_scan_keyid = PublicKey::From(keychain->GetScanSecret()).GetID();
    uint64_t& next_index = m_next_sender_key_indices[master_scan_keyid];
    if (next_index == std::numeric_limits<uint64_t>::max()) {
        return util::Error{Untranslated("MWEB sender key index exhausted")};
    }

    const SecretKey sender_key = keychain->GetSenderSigningKey(next_index);
    const uint64_t next_index_to_write = next_index + 1;
    wallet::WalletBatch batch(m_pWallet->GetDatabase());
    if (!m_pWallet->SetMinVersion(wallet::FEATURE_V24, &batch)) {
        return util::Error{Untranslated("Failed to write wallet minimum version")};
    }
    if (!batch.WriteMWEBNextSenderKeyIndex(master_scan_keyid, next_index_to_write)) {
        return util::Error{Untranslated("Failed to write MWEB sender key index")};
    }

    next_index = next_index_to_write;
    return sender_key;
}

void Wallet::LoadNextSenderKeyIndex(const CKeyID& master_scan_keyid, uint64_t next_index)
{
    AssertLockHeld(m_pWallet->cs_wallet);
    m_next_sender_key_indices[master_scan_keyid] = next_index;
}

std::optional<Wallet::SenderKeyMatch> Wallet::FindSenderKey(const PublicKey& sender_pubkey)
{
    const int64_t configured_keypool = gArgs.GetIntArg("-keypool", wallet::DEFAULT_KEYPOOL_SIZE);
    const uint64_t target_size = configured_keypool > 0 ? static_cast<uint64_t>(configured_keypool) : 1;

    for (const mw::Keychain::Ptr& keychain : GetAllKeychains()) {
        const CKeyID master_scan_keyid = PublicKey::From(keychain->GetScanSecret()).GetID();
        const uint64_t next_index = m_next_sender_key_indices[master_scan_keyid];
        const uint64_t range_end = next_index > std::numeric_limits<uint64_t>::max() - target_size
            ? std::numeric_limits<uint64_t>::max()
            : next_index + target_size;
        keychain->TopUpSenderPubKeys(range_end);

        const std::optional<uint64_t> index = keychain->LookupSenderPubKeyIndex(sender_pubkey);
        if (index.has_value()) {
            return SenderKeyMatch{
                keychain,
                master_scan_keyid,
                *index,
                keychain->GetSenderSigningKey(*index)
            };
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
    wallet::WalletBatch batch(m_pWallet->GetDatabase());
    if (!m_pWallet->SetMinVersion(wallet::FEATURE_V24, &batch)) {
        return false;
    }
    if (!batch.WriteMWEBNextSenderKeyIndex(master_scan_keyid, next_index_to_write)) {
        return false;
    }

    next_index = next_index_to_write;
    return true;
}

bool Wallet::RewindOutputSentByMe(const mw::Output& output, mw::WalletCoin& coin)
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

bool Wallet::RecoverOwnedOutputFromSenderData(const mw::Output& output, mw::WalletCoin& coin) const
{
    if (!coin.HasSharedSecret()) {
        return false;
    }

    const PublicKey subaddress_spend_pubkey = mw::RecoverSubaddressSpendPubKey(output.GetReceiverPubKey(), *coin.shared_secret);
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
        return true;
    }

    return false;
}
