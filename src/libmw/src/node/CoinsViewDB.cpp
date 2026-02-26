#include <mw/node/CoinsView.h>

#include <mw/db/CoinDB.h>
#include <mw/db/MMRInfoDB.h>
#include <mw/exceptions/ValidationException.h>
#include <mw/mmr/PruneList.h>

#include "CoinActions.h"

using namespace mw;

CoinsViewDB::Ptr CoinsViewDB::Open(
    const FilePath& datadir,
    const mw::Header::CPtr& pBestHeader,
    const mw::DBWrapper::Ptr& pDBWrapper)
{
    auto current_mmr_info = MMRInfoDB(pDBWrapper.get(), nullptr).GetLatest();
    uint32_t file_index = current_mmr_info ? current_mmr_info->index : 0;
    uint32_t compact_index = current_mmr_info ? current_mmr_info->compact_index : 0;

    auto pLeafSet = LeafSet::Open(datadir, file_index);
    auto pPruneList = PruneList::Open(datadir, compact_index);
    auto pOutputMMR = PMMR::Open('O', datadir, file_index, pDBWrapper, pPruneList);
    auto pView = new CoinsViewDB(pBestHeader, pDBWrapper, pLeafSet, pOutputMMR);

    return std::shared_ptr<CoinsViewDB>(pView);
}

mw::UTXO::CPtr CoinsViewDB::GetUTXO(const mw::Hash& output_id) const
{
    CoinDB coinDB(GetDatabase().get(), nullptr);
    return GetUTXO(coinDB, output_id);
}

mw::UTXO::CPtr CoinsViewDB::GetUTXO(const CoinDB& coinDB, const mw::Hash& output_id) const
{
    std::vector<uint8_t> value;

    auto utxos_by_hash = coinDB.GetUTXOs({output_id});
    auto iter = utxos_by_hash.find(output_id);
    if (iter != utxos_by_hash.cend()) {
        return iter->second;
    }

    return {};
}

void CoinsViewDB::AddUTXO(const uint64_t header_height, const mw::Output& output)
{
    CoinDB coinDB(GetDatabase().get(), nullptr);
    AddUTXO(coinDB, output);
}

void CoinsViewDB::AddUTXO(CoinDB& coinDB, const mw::Output& output)
{
    mmr::LeafIndex leafIdx = m_pOutputPMMR->Add(output.GetOutputID());
    m_pLeafSet->Add(leafIdx);

    AddUTXO(coinDB, std::make_shared<mw::UTXO>(GetBestHeader()->GetHeight(), std::move(leafIdx), output));
}

void CoinsViewDB::AddUTXO(CoinDB& coinDB, const mw::UTXO::CPtr& pUTXO)
{
    coinDB.AddUTXOs(std::vector<mw::UTXO::CPtr>{pUTXO});
}

mw::UTXO::CPtr CoinsViewDB::SpendUTXO(const mw::Hash& output_id)
{
    CoinDB coinDB(GetDatabase().get(), nullptr);
    return SpendUTXO(coinDB, output_id);
}

mw::UTXO::CPtr CoinsViewDB::SpendUTXO(CoinDB& coinDB, const mw::Hash& output_id)
{
    mw::UTXO::CPtr pUTXO = GetUTXO(coinDB, output_id);
    if (pUTXO == nullptr) {
		ThrowValidation(EConsensusError::UTXO_MISSING);
    }

    coinDB.RemoveUTXOs(std::vector<mw::Hash>{output_id});
    return pUTXO;
}

void CoinsViewDB::WriteBatch(const std::unique_ptr<mw::DBBatch>& pBatch, const CoinsViewUpdates& updates, const mw::Header::CPtr& pHeader)
{
    assert(pBatch != nullptr);
    SetBestHeader(pHeader);

    CoinDB coinDB(GetDatabase().get(), pBatch.get());
    for (const auto& actions : updates.GetActions()) {
        const mw::Hash& output_id = actions.first;
        for (const auto& action : actions.second) {
            if (action.IsSpend()) {
                SpendUTXO(coinDB, output_id);
            } else {
                AddUTXO(coinDB, action.pUTXO);
            }
        }
    }
}

void CoinsViewDB::Compact() const
{
    auto current_mmr_info = MMRInfoDB(GetDatabase().get(), nullptr)
                                .GetLatest();
    if (current_mmr_info) {
        m_pLeafSet->Cleanup(current_mmr_info->index);
        m_pOutputPMMR->Cleanup(current_mmr_info->index);
    }
}
