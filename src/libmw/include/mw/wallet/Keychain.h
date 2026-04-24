#pragma once

#include <mw/models/crypto/SecretKey.h>
#include <mw/models/tx/Output.h>
#include <mw/models/wallet/Coin.h>
#include <mw/models/wallet/StealthAddress.h>
#include <cstdint>
#include <memory>

// Forward Declarations
namespace wallet { class ScriptPubKeyMan; }

MW_NAMESPACE

class Keychain
{
public:
    using Ptr = std::shared_ptr<Keychain>;

    Keychain(const wallet::ScriptPubKeyMan* spk_man, SecretKey scan_secret, std::optional<PublicKey> spend_pubkey)
        : m_spk_man(spk_man),
        m_scanSecret(std::move(scan_secret)),
        m_spendPubkey(std::move(spend_pubkey)),
        m_spendSecret(std::nullopt) { }

    Keychain(const wallet::ScriptPubKeyMan* spk_man, SecretKey scan_secret, SecretKey spend_secret)
        : m_spk_man(spk_man),
        m_scanSecret(std::move(scan_secret)),
        m_spendPubkey(PublicKey::From(spend_secret)),
        m_spendSecret(std::move(spend_secret)) { }

    // If keychain is locked or watch-only (m_spendSecret is null),
    // this will still identify outputs belonging to the wallet, but
    // will not be able to calculate the coin's output key.
    // It will still calculate the shared_secret though, which can be
    // used to calculate the spend key when the wallet becomes unlocked.
    bool RewindOutput(const mw::Output& output, mw::Coin& coin) const;

    // Calculates the output secret key for the given coin.
    // If the address index is known, it calculates from the keychain's master spend key.
    // If not, it attempts to lookup the spend key in the database.
    // Returns boost::empty when keychain is locked or watch-only.
    std::optional<SecretKey> CalculateOutputSpendKey(const mw::Coin& coin) const;

    // Calculates the StealthAddress at the given index.
    // Requires that keychain be unlocked and not watch-only.
    StealthAddress GetStealthAddress(const uint32_t index) const;

    // Requires that keychain be unlocked and not watch-only.
    SecretKey GetSubaddressSpendKey(const uint32_t index) const;

    std::optional<uint32_t> LookupAddressIndex(const StealthAddress& address) const;

    const SecretKey& GetScanSecret() const noexcept { return m_scanSecret; }
    SecretKey GetRewindKey() const;
    SecretKey GetSenderKey(uint64_t index) const;

    bool HasSpendPubKey() const noexcept { return m_spendPubkey.has_value(); }
    bool HasSpendSecret() const noexcept { return m_spendSecret.has_value(); }

	// Clears the spend secret from memory, effectively making this a watch-only keychain.
    void Lock() { m_spendSecret.reset(); }
	
	// Reassigns the spend secret. To be used when unlocking the wallet.
    void Unlock(const SecretKey& spend_secret)
    {
        m_spendPubkey = PublicKey::From(spend_secret);
        m_spendSecret = spend_secret;
    }
    
private:
    const wallet::ScriptPubKeyMan* m_spk_man;
    SecretKey m_scanSecret;
    std::optional<PublicKey> m_spendPubkey;
    std::optional<SecretKey> m_spendSecret;
};

END_NAMESPACE
