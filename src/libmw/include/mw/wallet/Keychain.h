#pragma once

#include <mw/models/crypto/SecretKey.h>
#include <mw/models/wallet/StealthAddress.h>
#include <unordered_map>
#include <climits>
#include <memory>

MW_NAMESPACE

class Keychain
{
public:
    using Ptr = std::shared_ptr<Keychain>;

    Keychain(SecretKey scan_secret, SecretKey spend_secret, const uint32_t address_index_counter)
        : m_scanSecret(std::move(scan_secret)),
        m_spendSecret(std::move(spend_secret)),
        m_addressIndexCounter(address_index_counter) { }

    StealthAddress GetStealthAddress(const uint32_t index) const;
    SecretKey GetSpendKey(const uint32_t index) const;
    bool IsSpendPubKey(const PublicKey& spend_pubkey, uint32_t& index_out) const;

    const SecretKey& GetScanSecret() const noexcept { return m_scanSecret; }
    const SecretKey& GetSpendSecret() const noexcept { return m_spendSecret; }
    
private:
    SecretKey m_scanSecret;
    SecretKey m_spendSecret;

    mutable uint32_t m_addressIndexCounter;
    mutable std::unordered_map<PublicKey, uint32_t> m_pubkeys;
};

END_NAMESPACE