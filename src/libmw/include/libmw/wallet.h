#pragma once

#include "defs.h"
#include <boost/variant.hpp>

LIBMW_NAMESPACE

struct PegOutRecipient
{
    uint64_t amount;

    /// <summary>
    /// 4-42 bytes
    /// </summary>
    std::vector<uint8_t> scriptPubKey;
};

struct MWEBRecipient
{
    uint64_t amount;
    libmw::MWEBAddress address;
};

struct PegInRecipient
{
    uint64_t amount;
    libmw::MWEBAddress address;
};

typedef boost::variant<MWEBRecipient, PegInRecipient, PegOutRecipient> Recipient;

struct KeychainRef
{
    std::shared_ptr<mw::Keychain> pKeychain;

    /// <summary>
    /// Computes the MWEB wallet address with the given index.
    /// </summary>
    /// <param name="index">The index of the address keypair to use.</param>
    /// <returns>The generated stealth address.</returns>
    MWIMPORT MWEBAddress GetAddress(const uint32_t index);
};

WALLET_NAMESPACE

/// <summary>
/// Loads the wallet's keychain.
/// </summary>
/// <param name="scan_key">Scan private key generated with path m/1/0/100'</param>
/// <param name="spend_key">Spend private key generated with path m/1/0/101'</param>
/// <param name="address_index_counter">The highest index known to be used by the wallet.</param>
/// <returns>The loaded keychain</returns>
MWIMPORT KeychainRef LoadKeychain(
    const libmw::PrivateKey& scan_key,
    const libmw::PrivateKey& spend_key,
    const uint32_t address_index_counter
);

MWIMPORT libmw::TxRef CreateTx(
    const std::vector<libmw::Coin>& input_coins,
    const std::vector<libmw::Recipient>& recipients,
    const boost::optional<uint64_t>& pegin_amount,
    const uint64_t fee
);

MWIMPORT bool RewindBlockOutput(
    const libmw::KeychainRef& keychain,
    const libmw::BlockRef& block,
    const libmw::Commitment& output_commit,
    libmw::Coin& coin_out
);

MWIMPORT bool RewindTxOutput(
    const libmw::KeychainRef& keychain,
    const libmw::TxRef& tx,
    const libmw::Commitment& output_commit,
    libmw::Coin& coin_out
);

END_NAMESPACE // wallet
END_NAMESPACE // libmw