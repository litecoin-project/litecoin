#pragma once

#include <mw/common/Macros.h>
#include <mw/models/block/Header.h>
#include <mw/models/block/Block.h>
#include <mw/models/block/BlockUndo.h>
#include <mw/models/tx/Transaction.h>
#include <mw/models/tx/UTXO.h>
#include <mw/mmr/MMR.h>
#include <mw/mmr/LeafSet.h>
#include <libmw/interfaces/db_interface.h>
#include <memory>

// Forward Declarations
class CoinDB;

MW_NAMESPACE

struct CoinAction
{
    bool IsSpend() const noexcept { return pUTXO == nullptr; }

    UTXO::CPtr pUTXO;
};

class CoinsViewUpdates
{
public:
    using Ptr = std::shared_ptr<CoinsViewUpdates>;

    CoinsViewUpdates() = default;

    void AddUTXO(const UTXO::CPtr& pUTXO)
    {
        AddAction(pUTXO->GetCommitment(), CoinAction{ pUTXO });
    }

    void SpendUTXO(const Commitment& commitment)
    {
        AddAction(commitment, CoinAction{ nullptr });
    }

    const std::unordered_map<Commitment, std::vector<CoinAction>>& GetActions() const noexcept { return m_actions; }

    std::vector<CoinAction> GetActions(const Commitment& commitment) const noexcept
    {
        auto iter = m_actions.find(commitment);
        if (iter != m_actions.cend()) {
            return iter->second;
        }

        return {};
    }

    void Clear() noexcept
    {
        m_actions.clear();
    }

private:
    void AddAction(const Commitment commitment, CoinAction&& action)
    {
        auto iter = m_actions.find(commitment);
        if (iter != m_actions.end()) {
            std::vector<CoinAction>& actions = iter->second;
            actions.emplace_back(std::move(action));
        } else {
            std::vector<CoinAction> actions;
            actions.emplace_back(std::move(action));
            m_actions.insert({ commitment, actions });
        }
    }

    std::unordered_map<Commitment, std::vector<CoinAction>> m_actions;
};

//
// An interface for the various views of the extension block's UTXO set.
// This is similar to CCoinsView in the main codebase, and in fact, each CCoinsView
// should also hold an instance of a mw::ICoinsView for use with mimblewimble-related logic.
//
class ICoinsView : public std::enable_shared_from_this<ICoinsView>
{
public:
    using Ptr = std::shared_ptr<ICoinsView>;
    using CPtr = std::shared_ptr<const ICoinsView>;

    ICoinsView(const mw::Header::CPtr& pHeader, const std::shared_ptr<libmw::IDBWrapper>& pDBWrapper)
        : m_pHeader(pHeader), m_pDatabase(pDBWrapper) { }
    virtual ~ICoinsView() = default;

    void SetBestHeader(const mw::Header::CPtr& pHeader) noexcept { m_pHeader = pHeader; }
    mw::Header::CPtr GetBestHeader() const noexcept { return m_pHeader; }

    const std::shared_ptr<libmw::IDBWrapper>& GetDatabase() const noexcept { return m_pDatabase; }

    virtual bool IsCache() const noexcept = 0;

    // Virtual functions
    virtual std::vector<UTXO::CPtr> GetUTXOs(const Commitment& commitment) const = 0;
    virtual void WriteBatch(
        const libmw::IDBBatch::UPtr& pBatch,
        const CoinsViewUpdates& updates,
        const mw::Header::CPtr& pHeader
    ) = 0;

    virtual mmr::ILeafSet::Ptr GetLeafSet() const noexcept = 0;
    virtual mmr::IMMR::Ptr GetKernelMMR() const noexcept = 0;
    virtual mmr::IMMR::Ptr GetOutputPMMR() const noexcept = 0;
    
protected:
    void ValidateMMRs(const mw::Header::CPtr& pHeader) const;

private:
    mw::Header::CPtr m_pHeader;
    std::shared_ptr<libmw::IDBWrapper> m_pDatabase;
};

class CoinsViewCache : public mw::ICoinsView
{
public:
    using Ptr = std::shared_ptr<CoinsViewCache>;
    using CPtr = std::shared_ptr<const CoinsViewCache>;

    CoinsViewCache(const ICoinsView::Ptr& pBase)
        : ICoinsView(pBase->GetBestHeader(), pBase->GetDatabase()),
        m_pBase(pBase),
        m_pLeafSet(std::make_unique<mmr::LeafSetCache>(pBase->GetLeafSet())),
        m_pKernelMMR(std::make_unique<mmr::MMRCache>(pBase->GetKernelMMR())),
        m_pOutputPMMR(std::make_unique<mmr::MMRCache>(pBase->GetOutputPMMR())),
        m_pUpdates(std::make_shared<CoinsViewUpdates>()) { }

    bool IsCache() const noexcept final { return true; }

    std::vector<UTXO::CPtr> GetUTXOs(const Commitment& commitment) const noexcept final;
    mw::BlockUndo::CPtr ApplyBlock(const mw::Block::Ptr& pBlock);
    void UndoBlock(const mw::BlockUndo::CPtr& pUndo);
    void WriteBatch(
        const libmw::IDBBatch::UPtr& pBatch,
        const CoinsViewUpdates& updates,
        const mw::Header::CPtr& pHeader
    ) final;
    void Flush(const libmw::IDBBatch::UPtr& pBatch = nullptr);
    mw::Block::Ptr BuildNextBlock(const uint64_t height, const std::vector<mw::Transaction::CPtr>& transactions);

    void ValidateState() const;

    bool HasCoinInCache(const Commitment& commitment) const noexcept;

    mmr::ILeafSet::Ptr GetLeafSet() const noexcept final { return m_pLeafSet; }
    mmr::IMMR::Ptr GetKernelMMR() const noexcept final { return m_pKernelMMR; }
    mmr::IMMR::Ptr GetOutputPMMR() const noexcept final { return m_pOutputPMMR; }

private:
    void AddUTXO(const uint64_t header_height, const Output& output);
    UTXO SpendUTXO(const Commitment& commitment);

    ICoinsView::Ptr m_pBase;

    mmr::LeafSetCache::Ptr m_pLeafSet;
    mmr::MMRCache::Ptr m_pKernelMMR;
    mmr::MMRCache::Ptr m_pOutputPMMR;

    CoinsViewUpdates::Ptr m_pUpdates;
};

class CoinsViewDB : public mw::ICoinsView
{
public:
    CoinsViewDB(
        const mw::Header::CPtr& pBestHeader,
        const std::shared_ptr<libmw::IDBWrapper>& pDBWrapper,
        const mmr::LeafSet::Ptr& pLeafSet,
        const mmr::MMR::Ptr& pKernelMMR,
        const mmr::MMR::Ptr& pOutputPMMR
    ) : ICoinsView(pBestHeader, pDBWrapper),
        m_pLeafSet(pLeafSet),
        m_pKernelMMR(pKernelMMR),
        m_pOutputPMMR(pOutputPMMR) { }

    bool IsCache() const noexcept final { return false; }

    std::vector<UTXO::CPtr> GetUTXOs(const Commitment& commitment) const final;
    void WriteBatch(
        const libmw::IDBBatch::UPtr& pBatch,
        const CoinsViewUpdates& updates,
        const mw::Header::CPtr& pHeader
    ) final;

    mmr::ILeafSet::Ptr GetLeafSet() const noexcept final { return m_pLeafSet; }
    mmr::IMMR::Ptr GetKernelMMR() const noexcept final { return m_pKernelMMR; }
    mmr::IMMR::Ptr GetOutputPMMR() const noexcept final { return m_pOutputPMMR; }

private:
    void AddUTXO(CoinDB& coinDB, const Output& output);
    void AddUTXO(CoinDB& coinDB, const UTXO::CPtr& pUTXO);
    void SpendUTXO(CoinDB& coinDB, const Commitment& commitment);
    std::vector<UTXO::CPtr> GetUTXOs(const CoinDB& coinDB, const Commitment& commitment) const;

    mmr::LeafSet::Ptr m_pLeafSet;
    mmr::MMR::Ptr m_pKernelMMR;
    mmr::MMR::Ptr m_pOutputPMMR;
};

END_NAMESPACE