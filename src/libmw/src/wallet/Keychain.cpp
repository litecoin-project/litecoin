#include <mw/wallet/Keychain.h>
#include <mw/crypto/Hasher.h>
#include <mw/exceptions/CryptoException.h>
#include <mw/models/tx/OutputMask.h>
#include <wallet/scriptpubkeyman.h>
#include <key_io.h>

MW_NAMESPACE

bool Keychain::RewindOutput(const mw::Output& output, mw::WalletCoin& coin) const
{
    if (!m_spk_man) {
        return false;
    }

    auto scanned = ScanOutput(output);
    if (!scanned) {
        return false;
    }
    const auto address_index = LookupAddressIndex(*scanned->address);
    if (!address_index) {
        return false;
    }

    scanned->address_index = *address_index;
    coin = std::move(*scanned);
    return true;
}

std::optional<mw::WalletCoin> Keychain::ScanOutput(const mw::Output& output) const
{
    if (!output.HasStandardFields()) {
        return std::nullopt;
    }
    if (!output.Ko().IsValid() || !output.Ke().IsValid()) {
        return std::nullopt;
    }

    try {
        assert(!GetScanSecret().IsNull());
        const PublicKey shared_point = output.Ke().Mul(m_scanSecret);
        if (Hashed(EHashTag::TAG, shared_point)[0] != output.GetViewTag()) {
            return std::nullopt;
        }

        SecretKey shared_secret = SecretKey::FromHash(Hashed(EHashTag::DERIVE, shared_point));
        StealthAddress address = RecoverSubaddress(output.Ko(), shared_secret, m_scanSecret);

        // Calc blinding factor and unmask nonce and amount.
        OutputMask mask = OutputMask::FromShared(shared_secret);
        uint64_t value = mask.MaskValue(output.GetMaskedValue());
        BigInt<16> n = mask.MaskNonce(output.GetMaskedNonce());

        if (mask.SwitchCommit(value) != output.GetCommitment()) {
            return std::nullopt;
        }

        // Calculate Carol's sending key 's' and check that s*B ?= Ke
        SecretKey s = DeriveOutputSendKey(address, value, n);
        if (output.Ke() != DeriveOutputKeyExchangePubKey(address, s)) {
            return std::nullopt;
        }

        mw::WalletCoin rewound_coin;
        rewound_coin.blind = std::make_optional(mask.GetRawBlind());
        rewound_coin.amount = value;
        rewound_coin.output_id = output.GetOutputID();
        rewound_coin.address = address;
        rewound_coin.shared_secret = std::make_optional(std::move(shared_secret));
        rewound_coin.master_scan_key_id = m_scanKeyID;

        return rewound_coin;
    } catch (const CryptoException&) {
        return std::nullopt;
    }
}

std::optional<SecretKey> Keychain::CalculateOutputSpendKey(const mw::WalletCoin& coin) const
{
    if (!m_spk_man) {
        return std::nullopt;
    }

    if (!coin.HasSharedSecret() || !coin.IsMine()) {
        return std::nullopt;
    }

    if (coin.HasAddress()) {
        CKey key;
        if (m_spk_man->GetKey(coin.address->GetSpendPubKey().GetID(), key)) {
            return DeriveOutputSpendKey(SecretKey(key.begin()), *coin.shared_secret);
        }

        const auto* desc_spk_man = dynamic_cast<const wallet::DescriptorScriptPubKeyMan*>(m_spk_man);
        if (desc_spk_man && desc_spk_man->GetMWEBSpendKey(*coin.address, key)) {
            return DeriveOutputSpendKey(SecretKey(key.begin()), *coin.shared_secret);
        }
    }

    if (coin.HasAddress() && coin.address_index != UNKNOWN_INDEX && coin.address_index != CUSTOM_KEY && HasSpendPubKey() &&
        DeriveAddress(coin.address_index) != *coin.address) {
        return std::nullopt;
    }

    const auto* desc_spk_man = dynamic_cast<const wallet::DescriptorScriptPubKeyMan*>(m_spk_man);
    if (desc_spk_man && coin.address_index != UNKNOWN_INDEX && coin.address_index != CUSTOM_KEY) {
        CKey key;
        if (desc_spk_man->GetMWEBSpendKey(coin.address_index, key)) {
            return DeriveOutputSpendKey(SecretKey(key.begin()), *coin.shared_secret);
        }
    }

    // Watch-only or locked wallets will not have the master spend secret.
    if (!HasSpendSecret() || coin.address_index == CUSTOM_KEY) {
        return std::nullopt;
    }

    return DeriveOutputSpendKey(GetSubaddressSpendKey(coin.address_index), *coin.shared_secret);
}

StealthAddress Keychain::DeriveAddress(const uint32_t index) const
{
    assert(HasSpendPubKey());
    return DeriveSubaddress(*m_spendPubkey, m_scanSecret, index);
}

SecretKey Keychain::GetSubaddressSpendKey(const uint32_t index) const
{
    assert(HasSpendSecret());
    return DeriveSubaddressSpendKey(*m_spendSecret, m_scanSecret, index);
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
    return DeriveRewindKey(m_scanSecret);
}

SecretKey Keychain::GetSenderSigningKey(uint64_t index) const
{
    return DeriveSenderSigningKey(m_scanSecret, index);
}

END_NAMESPACE
