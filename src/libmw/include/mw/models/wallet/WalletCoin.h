#pragma once

#include <mw/common/Macros.h>
#include <mw/models/crypto/BlindingFactor.h>
#include <mw/models/crypto/Commitment.h>
#include <mw/models/wallet/StealthAddress.h>

#include <consensus/amount.h>
#include <support/cleanse.h>

#include <optional>

MW_NAMESPACE

/// <summary>
/// Change outputs will use the stealth address generated using index 0
/// </summary>
static constexpr uint32_t CHANGE_INDEX{0};

/// <summary>
/// Peg-in outputs will use the stealth address generated using index 1.
/// </summary>
static constexpr uint32_t PEGIN_INDEX{1};

/// <summary>
/// Outputs sent to a stealth address whose spend key was not generated using the MWEB
/// keychain won't have an address index. We use 0xfffffffe to represent this.
/// In that case, we must lookup the secret key in the wallet DB, rather than the MWEB keychain.
/// </summary>
static constexpr uint32_t CUSTOM_KEY{std::numeric_limits<uint32_t>::max() - 1};

/// <summary>
/// Outputs sent to others will be marked with an address_index of 0xffffffff.
/// </summary>
static constexpr uint32_t UNKNOWN_INDEX{std::numeric_limits<uint32_t>::max()};

/// <summary>
/// Represents an output owned by the wallet, or one sent by the wallet.
/// </summary>
struct WalletCoin : public Traits::ISerializable {
    static constexpr uint8_t LATEST_VERSION = 4;

    // Index of the subaddress this coin was received at.
    uint32_t address_index{UNKNOWN_INDEX};

    // The blinding factor of the coin's output.
    // May be empty for watch-only wallets.
    std::optional<BlindingFactor> blind;

    // The output amount in litoshis.
    // Typically positive, but could be 0 in the future when we start using decoys to improve privacy.
    CAmount amount;

    // The output's ID (hash).
    mw::Hash output_id;

    // The ephemeral private key used by the sender to create the output.
    std::optional<SecretKey> sender_key;

    // The StealthAddress the coin was sent to.
    std::optional<StealthAddress> address;

    // The shared secret used to generate the output key.
    // By storing this, we are able to postpone calculation of the spend key.
    // This allows us to scan for outputs while wallet is locked, and recalculate
    // the output key once the wallet becomes unlocked.
    std::optional<SecretKey> shared_secret;

    // The id the master scan key used to generate the stealth address.
    std::optional<CKeyID> master_scan_key_id;

    bool operator==(const WalletCoin& rhs) const
    {
        return std::tie(address_index, blind, amount, output_id, sender_key, address, shared_secret, master_scan_key_id) ==
            std::tie(rhs.address_index, rhs.blind, rhs.amount, rhs.output_id, rhs.sender_key, rhs.address, rhs.shared_secret, rhs.master_scan_key_id);
    }

    bool IsChange() const noexcept { return address_index == CHANGE_INDEX; }
    bool IsPegIn() const noexcept { return address_index == PEGIN_INDEX; }
    // A known address index means this is a wallet-owned output. Spend keys
    // are derived only while signing and are never retained by WalletCoin.
    bool IsMine() const noexcept { return address_index != UNKNOWN_INDEX; }
    bool HasAddress() const noexcept { return !!address; }
    bool HasSharedSecret() const noexcept { return !!shared_secret; }
    bool NeedsPersistenceUpgrade() const noexcept { return m_needs_persistence_upgrade; }
    bool HadPersistedSpendKey() const noexcept { return m_had_persisted_spend_key; }

    void Reset()
    {
        address_index = UNKNOWN_INDEX;
        blind = std::nullopt;
        amount = 0;
        output_id = mw::Hash();
        sender_key = std::nullopt;
        address = std::nullopt;
        shared_secret = std::nullopt;
        master_scan_key_id = std::nullopt;
        m_needs_persistence_upgrade = false;
        m_had_persisted_spend_key = false;
    }

    //
    // Basic serialization format (v0):
    //  - byte version
    //  - varint address_index
    //  - bool has_spend_key
    //    * byte[32] spend_key - skip if has_spend_key is false
    //  - bool has_blind
    //    * byte[32] blind - skip if has_blind is false
    //  - varint amount
    //  - byte[32] output_id
    //
    // If version >= 1, format extended to include:
    //  - bool has_sender_key
    //    * byte[32] sender_key - skip if has_sender_key is false
    //  - bool has_address
    //    * byte[33] address.scan_key - skip if has_address is false
    //    * byte[33] address.spend_key - skip if has_address is false
    //
    // If version >= 2, format extended to include:
    //  - bool has_shared_secret
    //    * byte[32] shared_secret - skip if has_shared_secret is false
    //
    // If version >= 3, format extended to include:
    //  - bool has_master_key_id
    //    * byte[20] master_scan_key_id - skip if has_master_key_id is false
    //
    // Version 4 removes spend_key. Versions 0-3 are accepted for migration,
    // but their spend key is consumed and discarded during deserialization.
    //
    IMPL_SERIALIZABLE(WalletCoin, obj)
    {
        // Always serialize using the latest version
        uint8_t version = LATEST_VERSION;
        READWRITE(version);
        if (version > LATEST_VERSION) {
            throw std::ios_base::failure("Unsupported WalletCoin version");
        }

        READWRITE(VARINT(obj.address_index));
        std::optional<SecretKey> legacy_spend_key;
        if (version < 4) {
            READWRITE(legacy_spend_key);
        }
        READWRITE(obj.blind);
        READWRITE(VARINT_MODE(obj.amount, VarIntMode::NONNEGATIVE_SIGNED));
        READWRITE(obj.output_id);

        if (version >= 1) {
            READWRITE(obj.sender_key);
            READWRITE(obj.address);
        }

        if (version >= 2) {
            READWRITE(obj.shared_secret);
        }

        if (version >= 3) {
            READWRITE(obj.master_scan_key_id);
        }

        SER_READ(obj, obj.m_needs_persistence_upgrade = version < LATEST_VERSION);
        SER_READ(obj, obj.m_had_persisted_spend_key = legacy_spend_key.has_value());
        if (ser_action.ForRead()) {
            if (legacy_spend_key) {
                memory_cleanse(legacy_spend_key->data(), legacy_spend_key->size());
            }
        }
    }

private:
    // Load-time migration state. These flags are never serialized.
    bool m_needs_persistence_upgrade{false};
    bool m_had_persisted_spend_key{false};
};

END_NAMESPACE
