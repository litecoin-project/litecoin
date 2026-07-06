#include <mw/node/CoinsView.h>
#include <mw/exceptions/ValidationException.h>
#include <mw/consensus/Aggregation.h>
#include <mw/consensus/KernelSumValidator.h>

#include "CoinActions.h"

using namespace mw;

CoinsViewCache::CoinsViewCache(const ICoinsView::Ptr& pBase)
    : ICoinsView(pBase->GetBestHeader(), pBase->GetDatabase()),
      m_pBase(pBase),
      m_pLeafSet(std::make_unique<LeafSetCache>(pBase->GetLeafSet())),
      m_pOutputPMMR(std::make_unique<PMMRCache>(pBase->GetOutputPMMR())),
      m_pUpdates(std::make_shared<CoinsViewUpdates>()) {}

Coin::CPtr CoinsViewCache::GetCoin(const mw::Hash& output_id) const noexcept
{
    Coin::CPtr pCoin = m_pBase->GetCoin(output_id);

    std::vector<CoinAction> actions = m_pUpdates->GetActions(output_id);
    for (const CoinAction& action : actions) {
        if (action.pCoin != nullptr) {
            assert(pCoin == nullptr);
            pCoin = action.pCoin;
        } else {
            assert(pCoin != nullptr);
            pCoin = nullptr;
        }
    }

    return pCoin;
}

mw::BlockUndo::CPtr CoinsViewCache::ApplyBlock(const mw::Block::CPtr& pBlock, const bool allow_historical_metadata_mismatch)
{
    assert(pBlock != nullptr);

    // Validate in a child cache before mutating this cache.
    mw::ICoinsView::Ptr pSelf(this, [](mw::ICoinsView*) {});
    mw::CoinsViewCache validation_cache(pSelf);

    mw::BlockUndo::CPtr pUndo = validation_cache.ApplyBlockChanges(pBlock, allow_historical_metadata_mismatch);
    validation_cache.Flush();
    return pUndo;
}

mw::BlockUndo::CPtr CoinsViewCache::ApplyBlockChanges(const mw::Block::CPtr& pBlock, const bool allow_historical_metadata_mismatch)
{
    auto pPreviousHeader = GetBestHeader();
    SetBestHeader(pBlock->GetHeader());

    BlindingFactor prev_offset = pPreviousHeader != nullptr ? pPreviousHeader->GetKernelOffset() : BlindingFactor();
    if (const auto sum_error = KernelSumValidator::ValidateForBlock(pBlock->GetTxBody(), pBlock->GetKernelOffset(), prev_offset)) {
        ThrowValidation(*sum_error);
    }

    std::vector<mw::Hash> coinsAdded;
    std::for_each(
        pBlock->GetOutputs().cbegin(), pBlock->GetOutputs().cend(),
        [this, &pBlock, &coinsAdded](const mw::Output& output) {
            AddCoin(pBlock->GetHeight(), output);
            coinsAdded.push_back(output.GetOutputID());
        }
    );

    std::vector<mw::Coin::CPtr> coinsSpent;
    std::for_each(
        pBlock->GetInputs().cbegin(), pBlock->GetInputs().cend(),
        [this, &coinsSpent, allow_historical_metadata_mismatch](const mw::Input& input) {
            mw::Coin::CPtr spentCoin = GetCoin(input.GetOutputID());
            if (spentCoin == nullptr || !m_pLeafSet->Contains(spentCoin->GetLeafIndex())) {
                ThrowValidation(EConsensusError::UTXO_MISSING);
            }

            if (!allow_historical_metadata_mismatch
                && (input.GetCommitment() != spentCoin->GetCommitment()
                    || input.GetOutputPubKey() != spentCoin->GetReceiverPubKey())) {
                ThrowValidation(EConsensusError::UTXO_MISMATCH);
            }

            spentCoin = SpendCoin(input.GetOutputID());
            coinsSpent.push_back(spentCoin);
        }
    );

    auto pHeader = pBlock->GetHeader();
    if (pHeader->GetOutputRoot() != GetOutputPMMR()->Root()
        || pHeader->GetNumTXOs() != GetOutputPMMR()->GetNumLeaves()
        || pHeader->GetLeafsetRoot() != GetLeafSet()->Root())
    {
        ThrowValidation(EConsensusError::MMR_MISMATCH);
    }

    return std::make_shared<mw::BlockUndo>(pPreviousHeader, std::move(coinsSpent), std::move(coinsAdded));
}

static const uint32_t MEMPOOL_HEIGHT = 0x7FFFFFFF;

void CoinsViewCache::AddTx(const mw::Transaction::CPtr& pTx)
{
    std::for_each(
        pTx->GetOutputs().cbegin(), pTx->GetOutputs().cend(),
        [this](const mw::Output& output) {
            AddCoin(MEMPOOL_HEIGHT, output);
        }
    );

    std::for_each(
        pTx->GetInputs().cbegin(), pTx->GetInputs().cend(),
        [this](const mw::Input& input) {
            SpendCoin(input.GetOutputID());
        }
    );
}

void CoinsViewCache::UndoBlock(const mw::BlockUndo::CPtr& pUndo)
{
    assert(pUndo != nullptr);

    std::vector<mmr::LeafIndex> leavesToAdd;
    for (const mw::Coin::CPtr& coinToAdd : pUndo->GetCoinsSpent()) {
        leavesToAdd.push_back(coinToAdd->GetLeafIndex());
        m_pUpdates->AddCoin(coinToAdd);
    }

    for (const mw::Hash& coinToRemove : pUndo->GetCoinsAdded()) {
        m_pUpdates->SpendCoin(coinToRemove);
    }

    auto pHeader = pUndo->GetPreviousHeader();
    if (pHeader == nullptr) {
        m_pLeafSet->Rewind(0, {});
        m_pOutputPMMR->Rewind(0);
        SetBestHeader(nullptr);
        return;
    }

    m_pLeafSet->Rewind(pHeader->GetNumTXOs(), leavesToAdd);
    m_pOutputPMMR->Rewind(pHeader->GetNumTXOs());
    SetBestHeader(pHeader);

    // Sanity check to make sure rewind applied successfully
    if (pHeader->GetOutputRoot() != m_pOutputPMMR->Root()
        || pHeader->GetNumTXOs() != m_pOutputPMMR->GetNumLeaves()
        || pHeader->GetLeafsetRoot() != m_pLeafSet->Root())
    {
        ThrowValidation(EConsensusError::MMR_MISMATCH);
    }
}

mw::Block::Ptr CoinsViewCache::BuildNextBlock(const uint64_t height, const std::vector<mw::Transaction::CPtr>& transactions)
{
    auto pTransaction = Aggregation::Aggregate(transactions);

    MemMMR::Ptr pKernelMMR = std::make_shared<MemMMR>();
    std::for_each(
        pTransaction->GetKernels().cbegin(), pTransaction->GetKernels().cend(),
        [&pKernelMMR](const mw::Kernel& kernel) { pKernelMMR->Add(kernel); }
    );

    std::for_each(
        pTransaction->GetOutputs().cbegin(), pTransaction->GetOutputs().cend(),
        [this, height](const mw::Output& output) { AddCoin(height, output); }
    );

    std::for_each(
        pTransaction->GetInputs().cbegin(), pTransaction->GetInputs().cend(),
        [this](const mw::Input& input) { SpendCoin(input.GetOutputID()); }
    );

    const uint64_t output_mmr_size = m_pOutputPMMR->GetNumLeaves();
    const uint64_t kernel_mmr_size = pKernelMMR->GetNumLeaves();

    mw::Hash output_root = m_pOutputPMMR->Root();
    mw::Hash kernel_root = pKernelMMR->Root();
    mw::Hash leafset_root = m_pLeafSet->Root();

    BlindingFactor kernel_offset = pTransaction->GetKernelOffset();
    if (GetBestHeader() != nullptr) {
        kernel_offset = Pedersen::AddBlindingFactors({
            GetBestHeader()->GetKernelOffset(),
            pTransaction->GetKernelOffset()
        });
    }

    BlindingFactor stealth_offset = pTransaction->GetStealthOffset();

    auto pHeader = std::make_shared<mw::Header>(
        height,
        std::move(output_root),
        std::move(kernel_root),
        std::move(leafset_root),
        std::move(kernel_offset),
        std::move(stealth_offset),
        output_mmr_size,
        kernel_mmr_size
    );

    return std::make_shared<mw::Block>(pHeader, pTransaction->GetBody());
}

bool CoinsViewCache::HasCoinInCache(const mw::Hash& output_id) const noexcept
{
    std::vector<CoinAction> actions = m_pUpdates->GetActions(output_id);
    if (!actions.empty()) {
        return !actions.back().IsSpend();
    }

    return false;
}

bool CoinsViewCache::HasSpendInCache(const mw::Hash& output_id) const noexcept
{
    std::vector<CoinAction> actions = m_pUpdates->GetActions(output_id);
    if (!actions.empty()) {
        return actions.back().IsSpend();
    }

    return false;
}

void CoinsViewCache::AddCoin(const uint64_t header_height, const mw::Output& output)
{
    Coin::CPtr pCoin = GetCoin(output.GetOutputID());
    if (pCoin != nullptr) {// && m_pLeafSet->Contains(pCoin->GetLeafIndex())) {
        ThrowValidation(EConsensusError::DUPLICATES);
    }

    mmr::LeafIndex leafIdx = m_pOutputPMMR->Add(output.GetOutputID());
    m_pLeafSet->Add(leafIdx);

    pCoin = std::make_shared<Coin>(header_height, std::move(leafIdx), output);

    m_pUpdates->AddCoin(pCoin);
}

mw::Coin::CPtr CoinsViewCache::SpendCoin(const mw::Hash& output_id)
{
    Coin::CPtr pCoin = GetCoin(output_id);
    if (pCoin == nullptr || !m_pLeafSet->Contains(pCoin->GetLeafIndex())) {
        ThrowValidation(EConsensusError::UTXO_MISSING);
    }

    m_pLeafSet->Remove(pCoin->GetLeafIndex());
    m_pUpdates->SpendCoin(output_id);

    return pCoin;
}

void CoinsViewCache::WriteBatch(CDBBatch*, const CoinsViewUpdates& updates, const mw::Header::CPtr& pHeader)
{
    SetBestHeader(pHeader);
     
    for (const auto& actions : updates.GetActions()) {
        const mw::Hash& output_id = actions.first;
        for (const auto& action : actions.second) {
            if (action.IsSpend()) {
                m_pUpdates->SpendCoin(output_id);
            } else {
                m_pUpdates->AddCoin(action.pCoin);
            }
        }
    }
}

void CoinsViewCache::Flush(CDBBatch* pBatch)
{
    // A null best header usually means MWEB has never activated, in which case there's
    // nothing to flush. But it also occurs after rewinding the first MWEB block: the
    // base still has a header and/or updates are pending, and skipping the flush then
    // would leave the base (and ultimately disk) holding the pre-rewind MWEB state.
    if (GetBestHeader() == nullptr && m_pBase->GetBestHeader() == nullptr && m_pUpdates->GetActions().empty()) {
        return;
    }

    m_pBase->WriteBatch(pBatch, *m_pUpdates, GetBestHeader());

    MMRInfo mmr_info = m_pBase->GetNextMMRInfo(pBatch);

    m_pLeafSet->Flush(mmr_info.index);
    m_pOutputPMMR->Flush(mmr_info.index, pBatch);

    m_pBase->SaveMMRInfo(pBatch, mmr_info);

    m_pUpdates->Clear();
}
