#pragma once

#include "defs.h"
#include <libmw/interfaces/chain_interface.h>
#include <libmw/interfaces/db_interface.h>

LIBMW_NAMESPACE
NODE_NAMESPACE

/// <summary>
/// Loads the state (MMRs mostly) into memory, and validates the current UTXO set.
/// </summary>
/// <param name="chainParams">The chain parameters to use.</param>
/// <param name="header">The possibly-null chain tip.</param>
/// <param name="pDBWrapper">A wrapper around the node database. Must not be null.</param>
/// <param name="log_callback">A callback to the logger print function.</param>
/// <returns>The CoinsViewDB which represents the state of the flushed chain.</returns>
MWIMPORT libmw::CoinsViewRef Initialize(
    const libmw::ChainParams& chainParams,
    const libmw::HeaderRef& header,
    const std::shared_ptr<libmw::IDBWrapper>& pDBWrapper,
    const std::function<void(const std::string&)>& log_callback
);

/// <summary>
/// Shuts down node and cleans up memory.
/// </summary>
MWIMPORT void Shutdown();

/// <summary>
/// Validates the chainstate and replaces the existing state if valid.
/// This should be used during initial sync, or when syncing from beyond the horizon.
/// </summary>
/// <param name="pChain">Provides access to MWEB headers and blocks. Must not be null.</param>
/// <param name="pCoinsDB">A wrapper around the node database. Must not be null.</param>
/// <param name="stateHeader">The MWEB header at the chain tip.</param>
/// <param name="state">The chainstate to validate and apply. Must not be null.</param>
/// <returns>The CoinsViewDB which represents the state of the flushed chain.</returns>
MWIMPORT libmw::CoinsViewRef ApplyState(
    const libmw::IChain::Ptr& pChain,
    const libmw::HeaderRef& stateHeader,
    const libmw::IDBWrapper::Ptr& pCoinsDB,
    const libmw::StateRef& state
);

/// <summary>
/// Context-free validation of the MW ext block.
/// This performs all consensus checks that don't require knowledge of the state.
/// </summary>
/// <param name="block">The MW ext block to validate. Must not be null.</param>
/// <param name="hash">The expected MWEB header hash.</param>
/// <param name="pegInCoins">The peg-in coins that are expected to be part of the MWEB.</param>
/// <param name="pegOutCoins">The peg-out coins that are expected to be part of the MWEB.</param>
/// <returns>True if the inputs are unspent.</returns>
MWIMPORT bool CheckBlock(
    const libmw::BlockRef& block,
    const libmw::BlockHash& hash,
    const std::vector<libmw::PegIn>& pegInCoins,
    const std::vector<libmw::PegOut>& pegOutCoins
);

/// <summary>
/// Validates and connects the MW ext block to the end of the chain in the given CoinsView.
/// </summary>
/// <pre>Block must be validated via CheckBlock before connecting it to the chain.</pre>
/// <param name="block">The block to connect. Must not be null.</param>
/// <param name="view">The CoinsView to connect the block to. Must not be null.</param>
/// <throws>ValidationException if consensus rules are not met.</throws>
MWIMPORT libmw::BlockUndoRef ConnectBlock(const libmw::BlockRef& block, const libmw::CoinsViewRef& view);

/// <summary>
/// Removes a MW ext block from the end of the chain in the given CoinsView.
/// </summary>
/// <param name="undoData">The MW ext block undo data to apply. Must not be null.</param>
/// <param name="view">The CoinsView to disconnect the block from. Must not be null.</param>
MWIMPORT void DisconnectBlock(const libmw::BlockUndoRef& undoData, const libmw::CoinsViewRef& view);

/// <summary>
/// Commits the changes from the cached CoinsView to the base CoinsView.
/// Adds the cached updates to the database if the base CoinsView is a DB view.
/// </summary>
/// <param name="view">The CoinsView cache whose changes will be committed. Must not be null.</param>
/// <param name="pBatch">The optional DB batch. This must be non-null when the base CoinsView is a DB view.</param>
MWIMPORT void FlushCache(
    const libmw::CoinsViewRef& view,
    const std::unique_ptr<libmw::IDBBatch>& pBatch = nullptr
);

/// <summary>
/// Creates an in-memory snapshot of the chainstate in the given CoinsView.
/// </summary>
/// <param name="view">The CoinsView containing the chainstate to snapshot. Must not be null.</param>
/// <returns>A non-null snapshot of the chainstate.</returns>
MWIMPORT libmw::StateRef SnapshotState(const libmw::CoinsViewRef& view);

/// <summary>
/// Context-free validation of the MWEB transaction.
/// This validates that the transaction is valid without checking for double-spends.
/// </summary>
/// <param name="transaction">The MWEB transaction to validate. Must not be null.</param>
/// <returns>True if transaction is valid.</returns>
MWIMPORT bool CheckTransaction(const libmw::TxRef& transaction);

/// <summary>
/// Validation of the MWEB transaction inputs against the given CoinsView.
/// This validates that the inputs are unspent, and their maturity is reached.
/// </summary>
/// <param name="view">The CoinsView to validate against. Must not be null.</param>
/// <param name="transaction">The MWEB transaction to validate. Must not be null.</param>
/// <param name="nSpendHeight">The height at which the transaction is included.</param>
/// <returns>True if the inputs are unspent.</returns>
MWIMPORT bool CheckTxInputs(const libmw::CoinsViewRef& view, const libmw::TxRef& transaction, uint64_t nSpendHeight);

/// <summary>
/// Checks if there's a unspent coin in the view with a matching commitment.
/// </summary>
/// <param name="view">The coins view to check.</param>
/// <param name="commitment">The commitment to look for.</param>
/// <returns>True if there's a matching unspent coin. Otherwise, false.</returns>
MWIMPORT bool HasCoin(const libmw::CoinsViewRef& view, const libmw::Commitment& commitment);

/// <summary>
/// Checks if there's a unspent coin with a matching commitment in the view that has not been flushed to the parent.
/// This is useful for checking if a coin is in the mempool but not yet on chain.
/// </summary>
/// <param name="view">The coins view to check.</param>
/// <param name="commitment">The commitment to look for.</param>
/// <returns>True if there's a matching unspent coin. Otherwise, false.</returns>
MWIMPORT bool HasCoinInCache(const libmw::CoinsViewRef& view, const libmw::Commitment& commitment);

END_NAMESPACE // node
END_NAMESPACE // libmw