#pragma once

// Copyright (c) 2018-2020 David Burkett
// Copyright (c) 2020-2021 The Litecoin Developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <array>
#include <set>
#include <vector>
#include <string>
#include <memory>
#include <cstdint>
#include <unordered_map>

#include <boost/filesystem.hpp>
#include <boost/optional.hpp>

#if defined(_WIN32)
//  Microsoft 
#ifdef LIBMW
#define MWEXPORT __declspec(dllexport)
#define MWIMPORT __declspec(dllexport)
#else
#define MWIMPORT __declspec(dllimport)
#endif
#elif defined(__GNUC__)
//  GCC
#define MWEXPORT __attribute__((visibility("default")))
#define MWIMPORT 
#else
#define MWEXPORT
#define MWIMPORT
#endif

#define LIBMW_NAMESPACE namespace libmw {
#define NODE_NAMESPACE namespace node {
#define MINER_NAMESPACE namespace miner {
#define DB_NAMESPACE namespace db {
#define WALLET_NAMESPACE namespace wallet {
#define END_NAMESPACE }

// Forward Declarations
namespace mw
{
    class Header;
    class Block;
    class BlockUndo;
    class Transaction;
    class ICoinsView;
    class BlockBuilder;
    struct State;
    class Keychain;
}

LIBMW_NAMESPACE

typedef std::array<uint8_t, 32> BlockHash;
typedef std::array<uint8_t, 32> KernelHash;
typedef std::array<uint8_t, 32> Offset;
typedef std::array<uint8_t, 32> BlindingFactor;
typedef std::array<uint8_t, 32> PrivateKey;
typedef std::array<uint8_t, 33> Commitment;
typedef std::array<uint8_t, 33> PubKey;
typedef std::pair<PubKey, PubKey> MWEBAddress;

static const uint8_t NORMAL_OUTPUT = 0;
static const uint8_t PEGIN_OUTPUT = 1;

/// <summary>
/// Consensus parameters
/// Any change to these will cause a hardfork!
/// </summary>
static constexpr size_t MAX_BLOCK_WEIGHT = 21'000;
static constexpr size_t KERNEL_WEIGHT = 2;
static constexpr size_t OWNER_SIG_WEIGHT = 1;
static constexpr size_t OUTPUT_WEIGHT = 18;
static constexpr uint16_t PEGIN_MATURITY = 20;
static constexpr uint8_t MAX_KERNEL_EXTRADATA_SIZE = 33;

/// <summary>
/// Change outputs will use the stealth address generated using index 2,000,000.
/// </summary>
static constexpr uint32_t CHANGE_INDEX{ 0 };

/// <summary>
/// Peg-in outputs will use the stealth address generated using index 2,000,000.
/// </summary>
static constexpr uint32_t PEGIN_INDEX{ 1 };

struct PegIn
{
    uint64_t amount;
    std::array<uint8_t, 33> commitment;

    bool operator==(const PegIn& rhs) const {
        return amount == rhs.amount && commitment == rhs.commitment;
    }

    bool operator!=(const PegIn& rhs) const {
        return !(*this == rhs);
    }
};

struct PegOut
{
    uint64_t amount;
    std::vector<uint8_t> scriptPubKey;
};

struct HeaderRef
{
    std::shared_ptr<const mw::Header> pHeader;
};

/// <summary>
/// A simple interface for accessing members of an MWEB block.
/// </summary>
struct BlockRef
{
    /// <summary>
    /// Checks whether the internal block pointer is null.
    /// If it's null, it is unsafe to call any other methods on this object.
    /// </summary>
    /// <returns>true if interal pointer is null. Otherwise, false.</returns>
    bool IsNull() const noexcept { return pBlock == nullptr; }

    MWIMPORT libmw::BlockHash GetHash() const noexcept;
    MWIMPORT libmw::HeaderRef GetHeader() const noexcept;
    MWIMPORT uint64_t GetTotalFee() const noexcept;
    MWIMPORT uint64_t GetWeight() const noexcept;
    MWIMPORT std::set<KernelHash> GetKernelHashes() const noexcept;
    MWIMPORT std::vector<libmw::Commitment> GetInputCommits() const noexcept;
    MWIMPORT std::vector<libmw::Commitment> GetOutputCommits() const noexcept;

    std::shared_ptr<mw::Block> pBlock;
};

/// <summary>
/// A wrapper around an internal pointer to a BlockUndo object.
/// </summary>
struct BlockUndoRef
{
    std::shared_ptr<const mw::BlockUndo> pUndo;
};

/// <summary>
/// A simple interface for accessing members of an MWEB transaction.
/// </summary>
struct TxRef
{
    MWIMPORT std::vector<libmw::PegOut> GetPegouts() const noexcept;
    MWIMPORT std::vector<libmw::PegIn> GetPegins() const noexcept;
    MWIMPORT uint64_t GetTotalFee() const noexcept;
    MWIMPORT uint64_t GetWeight() const noexcept;
    MWIMPORT std::set<KernelHash> GetKernelHashes() const noexcept;
    MWIMPORT std::set<libmw::Commitment> GetInputCommits() const noexcept;
    MWIMPORT std::set<libmw::Commitment> GetOutputCommits() const noexcept;

    std::shared_ptr<const mw::Transaction> pTransaction;
};

/// <summary>
/// A wrapper around an internal pointer to a coin view.
/// This can either be a CoinsViewDB, which represents the flushed view, or a CoinsViewCache.
/// When the node is instantiated, a single CoinsViewDB is created.
/// Every other CoinView is a cache built directly on top of that, or on top of other caches.
/// </summary>
struct CoinsViewRef
{
    /// <summary>
    /// Creates a new CoinsViewCache on top of this CoinsView.
    /// </summary>
    /// <returns>A wrapper around the newly created CoinsViewCache, or null if the current view is null.</returns>
    MWIMPORT CoinsViewRef CreateCache() const;

    std::shared_ptr<mw::ICoinsView> pCoinsView;
};

struct StateRef
{
    std::shared_ptr<mw::State> pState;
};

struct ChainParams
{
    boost::filesystem::path dataDirectory;
    std::string hrp;
};

struct BlockBuilderRef
{
    std::shared_ptr<mw::BlockBuilder> pBuilder;
};

/// <summary>
/// Represents an output owned by the wallet, and the keys necessary to spend it.
/// </summary>
struct Coin
{
    // 0 for typical outputs or 1 for pegged-in outputs
    // This is used to determine the required number of confirmations before spending.
    uint8_t features;

    // Index of the subaddress this coin was received at.
    uint32_t address_index;

    // The private key needed in order to spend the coin.
    // May be empty for watch-only wallets.
    boost::optional<libmw::BlindingFactor> key;

    // The blinding factor needed in order to spend the coin.
    // May be empty for watch-only wallets.
    boost::optional<libmw::BlindingFactor> blind;

    // The output amount in litoshis.
    // Typically positive, but could be 0 in the future when we start using decoys to improve privacy.
    uint64_t amount;

    // The output commitment (v*H + r*G).
    libmw::Commitment commitment;

    bool IsChange() const noexcept { return address_index == CHANGE_INDEX; }
    bool IsPegIn() const noexcept { return address_index == PEGIN_INDEX; }
};

END_NAMESPACE