#include <mw/wallet/Keychain.h>
#include <mw/crypto/Hasher.h>
#include <mw/crypto/SecretKeys.h>
#include <mw/models/tx/OutputMask.h>
#include <wallet/scriptpubkeyman.h>
#include <key_io.h>

MW_NAMESPACE

bool Keychain::RewindOutput(const mw::Output& output, mw::WalletCoin& coin) const
{
    if (!m_spk_man) {
        return false;
    }
    if (!output.HasStandardFields()) {
        return false;
    }

    assert(!GetScanSecret().IsNull());
    PublicKey shared_secret_pk = output.Ke().Mul(GetScanSecret());
    uint8_t view_tag = Hashed(EHashTag::TAG, shared_secret_pk)[0];
    if (view_tag != output.GetViewTag()) {
        return false;
    }

    SecretKey shared_secret = Hashed(EHashTag::DERIVE, shared_secret_pk);
    PublicKey B_i = output.Ko().Div(Hashed(EHashTag::OUT_KEY, shared_secret));

    // Check if B_i belongs to wallet
    StealthAddress address(B_i.Mul(m_scanSecret), B_i);
    const std::optional<uint32_t> address_index = LookupAddressIndex(address);
    if (!address_index) {
        return false;
    }

    // Calc blinding factor and unmask nonce and amount.
    OutputMask mask = OutputMask::FromShared(shared_secret);
    uint64_t value = mask.MaskValue(output.GetMaskedValue());
    BigInt<16> n = mask.MaskNonce(output.GetMaskedNonce());

    if (mask.SwitchCommit(value) != output.GetCommitment()) {
        return false;
    }

    // Calculate Carol's sending key 's' and check that s*B ?= Ke
    SecretKey s = Hasher(EHashTag::SEND_KEY)
        .Append(address.A())
        .Append(address.B())
        .Append(value)
        .Append(n)
        .hash();
    if (output.Ke() != address.B().Mul(s)) {
        return false;
    }

    coin.address_index = *address_index;
    coin.blind = std::make_optional(mask.GetRawBlind());
    coin.amount = value;
    coin.output_id = output.GetOutputID();
    coin.address = address;
    coin.shared_secret = std::make_optional(std::move(shared_secret));
    coin.spend_key = CalculateOutputSpendKey(coin);
    coin.master_scan_key_id = PublicKey::From(m_scanSecret).GetID();

    return true;
}

std::optional<SecretKey> Keychain::CalculateOutputSpendKey(const mw::WalletCoin& coin) const
{
    // If we already calculated the spend key, there's no need to calculate it again.
    if (coin.HasSpendKey()) {
        return coin.spend_key;
    }
    
    if (!m_spk_man) {
        return std::nullopt;
    }

    if (!coin.HasSharedSecret() || !coin.IsMine()) {
        return std::nullopt;
    }

    auto derive_output_key = [](const SecretKey& subaddress_spend_key, const SecretKey& shared_secret) -> SecretKey {
        return SecretKeys::From(subaddress_spend_key)
            .Mul(Hashed(EHashTag::OUT_KEY, shared_secret))
            .Total();
    };

    if (coin.HasAddress()) {
        CKey key;
        if (m_spk_man->GetKey(coin.address->GetSpendPubKey().GetID(), key)) {
            return derive_output_key(SecretKey(key.begin()), *coin.shared_secret);
        }

        const auto* desc_spk_man = dynamic_cast<const wallet::DescriptorScriptPubKeyMan*>(m_spk_man);
        if (desc_spk_man && desc_spk_man->GetMWEBSpendKey(*coin.address, key)) {
            return derive_output_key(SecretKey(key.begin()), *coin.shared_secret);
        }
    }

    if (coin.HasAddress() && coin.address_index != UNKNOWN_INDEX && coin.address_index != CUSTOM_KEY && HasSpendPubKey() &&
        GetStealthAddress(coin.address_index) != *coin.address) {
        return std::nullopt;
    }

    const auto* desc_spk_man = dynamic_cast<const wallet::DescriptorScriptPubKeyMan*>(m_spk_man);
    if (desc_spk_man && coin.address_index != UNKNOWN_INDEX && coin.address_index != CUSTOM_KEY) {
        CKey key;
        if (desc_spk_man->GetMWEBSpendKey(coin.address_index, key)) {
            return derive_output_key(SecretKey(key.begin()), *coin.shared_secret);
        }
    }

    // Watch-only or locked wallets will not have the master spend secret.
    if (!HasSpendSecret() || coin.address_index == CUSTOM_KEY) {
        return std::nullopt;
    }

    return derive_output_key(GetSubaddressSpendKey(coin.address_index), *coin.shared_secret);
}

StealthAddress Keychain::GetStealthAddress(const uint32_t index) const
{
    assert(HasSpendPubKey());

    SecretKey mi = Hasher(EHashTag::ADDRESS)
        .Append<uint32_t>(index)
        .Append(m_scanSecret)
        .hash();
    PublicKey Bi = m_spendPubkey->Add(mi);
    PublicKey Ai = Bi.Mul(m_scanSecret);

    return StealthAddress(Ai, Bi);
}

SecretKey Keychain::GetSubaddressSpendKey(const uint32_t index) const
{
    assert(HasSpendSecret());

    SecretKey mi = Hasher(EHashTag::ADDRESS)
        .Append<uint32_t>(index)
        .Append(m_scanSecret)
        .hash();

    return SecretKeys::From(*m_spendSecret).Add(mi).Total();
}

std::optional<uint32_t> Keychain::LookupAddressIndex(const StealthAddress& address) const
{
    const auto* desc_spk_man = dynamic_cast<const wallet::DescriptorScriptPubKeyMan*>(m_spk_man);
    auto pMetadata = m_spk_man->GetMetadata(address);
    if (pMetadata) {
        if (pMetadata->key_origin.hdkeypath.mweb_index.has_value()) {
            return pMetadata->key_origin.hdkeypath.mweb_index.value();
        }

        if (desc_spk_man) {
            const std::optional<uint32_t> address_index = desc_spk_man->GetMWEBAddressIndex(address);
            if (address_index) {
                return address_index;
            }
        }

        // v0.21.2 incorrectly generated MWEB keys from the pre-split keypool for upgraded wallets.
        // These keys will not have an mweb_index, so we set the address_index as CUSTOM_KEY.
        return CUSTOM_KEY;
    }

    if (desc_spk_man) {
        return desc_spk_man->GetMWEBAddressIndex(address);
    }

    return std::nullopt;
}

SecretKey Keychain::GetRewindKey() const
{
    return SecretKey(Hashed(EHashTag::REWIND_KEY, m_scanSecret).data());
}

SecretKey Keychain::GetSenderKey(uint64_t index) const
{
    const SecretKey sender_root(Hashed(EHashTag::SENDER_ROOT, m_scanSecret).data());
    SecretKey sender_key = Hasher(EHashTag::SENDER_ROOT)
        .Append(sender_root)
        .Append(index)
        .hash();
    SecretKeys normalized = SecretKeys::From(sender_key);
    return normalized.Total();
}

END_NAMESPACE
