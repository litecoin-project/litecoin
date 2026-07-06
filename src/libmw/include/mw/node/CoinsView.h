#pragma once

#include <mw/common/Macros.h>
#include <mw/models/block/Header.h>
#include <mw/models/block/Block.h>
#include <mw/models/block/BlockUndo.h>
#include <mw/models/tx/Transaction.h>
#include <mw/models/tx/Coin.h>
#include <mw/mmr/MMR.h>
#include <mw/mmr/MMRInfo.h>
#include <mw/mmr/LeafSet.h>
#include <memory>

// Forward Declarations
class CoinDB;
class CoinsViewUpdates;

MW_NAMESPACE

//
// An interface for the various views of the extension block's coin set.
// This is similar to CCoinsView in the main codebase, and in fact, each CCoinsView
// should also hold an instance of a mw::ICoinsView for use with MWEB-related logic.
//
class ICoinsView
{
public:
    using Ptr = std::shared_ptr<ICoinsView>;
    using CPtr = std::shared_ptr<const ICoinsView>;

    ICoinsView(const mw::Header::CPtr& pHeader, CDBWrapper* pDBWrapper)
        : m_pHeader(pHeader), m_pDatabase(pDBWrapper) { }
    virtual ~ICoinsView() = default;

    void SetBestHeader(const mw::Header::CPtr& pHeader) noexcept { m_pHeader = pHeader; }
    mw::Header::CPtr GetBestHeader() const noexcept { return m_pHeader; }

    CDBWrapper* GetDatabase() const noexcept { return m_pDatabase; }

    // Virtual functions
    virtual bool IsCache() const noexcept = 0;

    virtual mw::Coin::CPtr GetCoin(const mw::Hash& output_id) const = 0;
    virtual void AddCoin(const uint64_t header_height, const mw::Output& output) = 0;
    virtual mw::Coin::CPtr SpendCoin(const mw::Hash& output_id) = 0;

    virtual void WriteBatch(
        CDBBatch* pBatch,
        const CoinsViewUpdates& updates,
        const mw::Header::CPtr& pHeader
    ) = 0;

    virtual ILeafSet::Ptr GetLeafSet() const noexcept = 0;
    virtual IMMR::Ptr GetOutputPMMR() const noexcept = 0;

    /// <summary>
    /// Checks if there's an unspent coin in the view with a matching ID.
    /// </summary>
    /// <param name="output_id">The output ID of the coin to look for.</param>
    /// <returns>True if there's a matching unspent coin. Otherwise, false.</returns>
    bool HasCoin(const mw::Hash& output_id) const noexcept { return GetCoin(output_id) != nullptr; }

    /// <summary>
    /// Checks if there's an unspent coin with a matching ID in the view that has not been flushed to the parent.
    /// This is useful for checking if a coin is in the mempool but not yet on chain.
    /// </summary>
    /// <param name="output_id">The output ID of the coin to look for.</param>
    /// <returns>True if there's a matching unspent coin. Otherwise, false.</returns>
    virtual bool HasCoinInCache(const mw::Hash& output_id) const noexcept = 0;

    /// <summary>
    /// Cleanup any old MMR files that no longer reflect the latest flushed state.
    /// </summary>
    virtual void Compact() const = 0;

    virtual MMRInfo GetNextMMRInfo(CDBBatch* pBatch) const = 0;
    virtual void SaveMMRInfo(CDBBatch* pBatch, const MMRInfo& mmr_info) = 0;

private:
    mw::Header::CPtr m_pHeader;
    CDBWrapper* m_pDatabase;
};

class CoinsViewCache : public mw::ICoinsView
{
public:
    using Ptr = std::shared_ptr<CoinsViewCache>;
    using CPtr = std::shared_ptr<const CoinsViewCache>;

    explicit CoinsViewCache(const ICoinsView::Ptr& pBase);

    bool IsCache() const noexcept final { return true; }

    mw::Coin::CPtr GetCoin(const mw::Hash& output_id) const noexcept final;
    void AddCoin(const uint64_t header_height, const mw::Output& output) final;
    mw::Coin::CPtr SpendCoin(const mw::Hash& output_id) final;

    /// <summary>
    /// Validates and connects the block to the end of the chain.
    /// Consumer is required to call ValidateBlock first.
    /// </summary>
    /// <pre>Block must be validated via CheckBlock before connecting it to the chain.</pre>
    /// <param name="pBlock">The block to connect. Must not be null.</param>
    /// <throws>ValidationException if consensus rules are not met.</throws>
    mw::BlockUndo::CPtr ApplyBlock(const mw::Block::CPtr& pBlock, const bool allow_historical_metadata_mismatch = false);

    void AddTx(const mw::Transaction::CPtr& pTx);

    /// <summary>
    /// Removes a block from the end of the chain.
    /// </summary>
    /// <param name="pUndo">The MWEB undo data to apply. Must not be null.</param>
    void UndoBlock(const mw::BlockUndo::CPtr& pUndo);

    void WriteBatch(
        CDBBatch* pBatch,
        const CoinsViewUpdates& updates,
        const mw::Header::CPtr& pHeader
    ) final;
    void Compact() const final { m_pBase->Compact(); }
    MMRInfo GetNextMMRInfo(CDBBatch*) const final { return {}; }
    void SaveMMRInfo(CDBBatch*, const MMRInfo&) final {}

    /// <summary>
    /// Commits the changes from the cached CoinsView to the base CoinsView.
    /// Adds the cached updates to the database if the base CoinsView is a DB view.
    ///
    /// When flushing to a DB view, this writes and fsyncs a new generation of
    /// the MMR/leafset files before staging the leveldb entries (coins, leaves,
    /// MMRInfo) in pBatch; the state only becomes visible when the caller
    /// commits the batch, so a crash at any point leaves the previous
    /// generation intact.
    ///
    /// This is NOT atomic against exceptions: a throw mid-flush can leave the
    /// base's in-memory LeafSet/PMMR one step ahead of the (uncommitted) batch.
    /// The individual steps are exception-safe (no unmapped state, pending
    /// changes retained, orphan new-generation files are overwritten by later
    /// flushes), but a caller flushing to disk MUST discard pBatch, MUST NOT
    /// retry, and MUST treat the failure as fatal for this chainstate — see
    /// CCoinsViewDB::BatchWrite, which latches the failure and aborts the node.
    /// </summary>
    /// <param name="pBatch">The optional DB batch. This must be non-null when the base CoinsView is a DB view.</param>
    /// <throws>FileException/DatabaseException if writing the new state fails.</throws>
    void Flush(CDBBatch* pBatch = nullptr);

    mw::Block::Ptr BuildNextBlock(const uint64_t height, const std::vector<mw::Transaction::CPtr>& transactions);

    bool HasCoinInCache(const mw::Hash& output_id) const noexcept final;
    bool HasSpendInCache(const mw::Hash& output_id) const noexcept;

    ILeafSet::Ptr GetLeafSet() const noexcept final { return m_pLeafSet; }
    IMMR::Ptr GetOutputPMMR() const noexcept final { return m_pOutputPMMR; }

private:
    mw::BlockUndo::CPtr ApplyBlockChanges(const mw::Block::CPtr& pBlock, const bool allow_historical_metadata_mismatch);

    ICoinsView::Ptr m_pBase;

    LeafSetCache::Ptr m_pLeafSet;
    PMMRCache::Ptr m_pOutputPMMR;

    std::shared_ptr<CoinsViewUpdates> m_pUpdates;
};

class CoinsViewDB : public mw::ICoinsView
{
public:
    using Ptr = std::shared_ptr<CoinsViewDB>;

    static CoinsViewDB::Ptr Open(
        const FilePath& datadir,
        const mw::Header::CPtr& pBestHeader,
        CDBWrapper* pDBWrapper
    );

    bool IsCache() const noexcept final { return false; }

    mw::Coin::CPtr GetCoin(const mw::Hash& output_id) const final;
    void AddCoin(const uint64_t header_height, const mw::Output& output) final;
    mw::Coin::CPtr SpendCoin(const mw::Hash& output_id) final;

    void WriteBatch(
        CDBBatch* pBatch,
        const CoinsViewUpdates& updates,
        const mw::Header::CPtr& pHeader
    ) final;
    void Compact() const final;
    MMRInfo GetNextMMRInfo(CDBBatch* pBatch) const final;
    void SaveMMRInfo(CDBBatch* pBatch, const MMRInfo& mmr_info) final;

    ILeafSet::Ptr GetLeafSet() const noexcept final { return m_pLeafSet; }
    IMMR::Ptr GetOutputPMMR() const noexcept final { return m_pOutputPMMR; }

    bool HasCoinInCache(const mw::Hash& output_id) const noexcept final { return false; }

private:
    CoinsViewDB(
        const mw::Header::CPtr& pBestHeader,
        CDBWrapper* pDBWrapper,
        const LeafSet::Ptr& pLeafSet,
        const PMMR::Ptr& pOutputPMMR
    ) : ICoinsView(pBestHeader, pDBWrapper),
        m_pLeafSet(pLeafSet),
        m_pOutputPMMR(pOutputPMMR) { }

    void AddCoin(CoinDB& coinDB, const mw::Output& output);
    void AddCoin(CoinDB& coinDB, const mw::Coin::CPtr& pCoin);
    mw::Coin::CPtr SpendCoin(CoinDB& coinDB, const mw::Hash& output_id);
    mw::Coin::CPtr GetCoin(const CoinDB& coinDB, const mw::Hash& output_id) const;

    LeafSet::Ptr m_pLeafSet;
    PMMR::Ptr m_pOutputPMMR;
};

END_NAMESPACE
