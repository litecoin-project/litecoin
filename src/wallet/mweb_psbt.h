// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <mw/models/wallet/WalletCoin.h>
#include <mw/wallet/Keychain.h>
#include <mw/wallet/sign.h>
#include <psbt.h>
#include <util/result.h>

#include <map>
#include <optional>
#include <string>
#include <unordered_map>

//! Key material extracted from a single-address MWEB descriptor string.
struct MWEBAddressDescriptorData
{
    StealthAddress address{};
    std::optional<SecretKey> scan_secret{std::nullopt};
    std::optional<SecretKey> subaddress_spend_secret{std::nullopt};
};

//! Parses a single-address MWEB output descriptor, extracting any private keys it carries.
util::Result<MWEBAddressDescriptorData> ParseMWEBAddressDescriptor(const std::string& descriptor_str);

//! Read-only view of the wallet state needed to resolve MWEB input keys.
class MWEBSigningKeyStore
{
public:
    virtual ~MWEBSigningKeyStore() = default;
    virtual std::optional<mw::WalletCoin> GetWalletCoin(const mw::Hash& output_id) const = 0;
    virtual mw::Keychain::Ptr GetKeychain(const CKeyID& master_scan_key_id) const = 0;
    virtual std::optional<std::string> InferAddressDescriptor(const mw::WalletCoin& coin) const = 0;
};

/**
 * Resolves the key material for one MWEB PSBT input (the PSBT Updater role).
 *
 * Fills input.mweb_address_descriptor and input.mweb_shared_secret in place
 * where they can be determined from the keystore or derived from the input's
 * own fields. Returns the input's spend key if one could be resolved, nullopt
 * if not (which is not an error — another signer may hold the key), or an
 * error if the descriptor is invalid or inconsistent with the input.
 */
util::Result<std::optional<SecretKey>> ResolveMWEBInputKeys(PSBTInput& input, const MWEBSigningKeyStore& keystore);

/**
 * Result of the MWEB signing stage.
 *
 * The script-signing stage requires one of these before it may build sighash
 * precomputation data, so a PSBT cannot reach script signing without the
 * MWEB-signing decision having been made first (see SignPSBTMWEBComponents,
 * which may rewrite peg-in scripts and thereby invalidate precomputed data).
 */
struct MWEBSignOutcome
{
    //! Wallet coins discovered while signing, keyed by output ID.
    std::map<mw::Hash, mw::WalletCoin> discovered_coins;

    //! Outcome for a PSBT where MWEB signing was skipped. Only valid when no
    //! peg-in script rewrite is possible (no MWEB components, or not signing).
    static MWEBSignOutcome Skipped() { return {}; }
};

/**
 * Signs the MWEB components of the PSBT and propagates the finalized data
 * back into the PSBT input/output/kernel fields and global offsets.
 *
 * This may rewrite peg-in output scripts in psbtx.outputs, so any
 * PrecomputedTransactionData built before this call must be rebuilt afterward.
 */
util::Result<MWEBSignOutcome> SignPSBTMWEBComponents(
    PartiallySignedTransaction& psbtx,
    const std::unordered_map<mw::Hash, SecretKey>& spend_keys,
    const SecretKey& rewind_key,
    const mw::SenderKeyGenerator& generate_sender_key
);
