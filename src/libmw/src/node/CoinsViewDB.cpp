#include <mw/node/CoinsView.h>

#include "models/CoinKey.h"
#include "models/CoinEntry.h"

#include <mw/db/CoinDB.h>
#include <mw/exceptions/ValidationException.h>

MW_NAMESPACE

std::vector<UTXO::CPtr> CoinsViewDB::GetUTXOs(const Commitment& commitment) const
{
    CoinDB coinDB(GetDatabase().get(), nullptr);
    return GetUTXOs(coinDB, commitment);
}

std::vector<UTXO::CPtr> CoinsViewDB::GetUTXOs(const CoinDB& coinDB, const Commitment& commitment) const
{
    std::vector<uint8_t> value;

    auto utxos_by_commitment = coinDB.GetUTXOs({ commitment });
    auto iter = utxos_by_commitment.find(commitment);
    if (iter != utxos_by_commitment.cend()) {
        return { iter->second };
    }

    return {};
}

void CoinsViewDB::AddUTXO(CoinDB& coinDB, const Output& output)
{
    mmr::LeafIndex leafIdx = m_pOutputPMMR->Add(output.ToOutputId());
    m_pLeafSet->Add(leafIdx);

    AddUTXO(coinDB, std::make_shared<UTXO>(GetBestHeader()->GetHeight(), std::move(leafIdx), output));
}

void CoinsViewDB::AddUTXO(CoinDB& coinDB, const UTXO::CPtr& pUTXO)
{
    const Commitment& commitment = pUTXO->GetOutput().GetCommitment();
    std::vector<UTXO::CPtr> utxos = GetUTXOs(coinDB, commitment);
    utxos.push_back(pUTXO);

    coinDB.AddUTXOs(std::vector<UTXO::CPtr>{ pUTXO });
}

void CoinsViewDB::SpendUTXO(CoinDB& coinDB, const Commitment& commitment)
{
    std::vector<UTXO::CPtr> utxos = GetUTXOs(coinDB, commitment);
    if (utxos.empty()) {
		ThrowValidation(EConsensusError::UTXO_MISSING);
    }

    coinDB.RemoveUTXOs(std::vector<Commitment>{ commitment });
}

void CoinsViewDB::WriteBatch(const std::unique_ptr<libmw::IDBBatch>& pBatch, const CoinsViewUpdates& updates, const mw::Header::CPtr& pHeader)
{
    assert(pBatch != nullptr);
    SetBestHeader(pHeader);

    CoinDB coinDB(GetDatabase().get(), pBatch.get());
    for (const auto& actions : updates.GetActions()) {
        const Commitment& commitment = actions.first;
        for (const auto& action : actions.second) {
            if (action.IsSpend()) {
                SpendUTXO(coinDB, commitment);
            } else {
                AddUTXO(coinDB, action.pUTXO);
            }
        }
    }
}

END_NAMESPACE