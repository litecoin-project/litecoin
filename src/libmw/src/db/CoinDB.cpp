#include <mw/db/CoinDB.h>
#include "common/Database.h"

static const DBTable UTXO_TABLE = { 'U' };

CoinDB::CoinDB(mw::DBWrapper* pDBWrapper, mw::DBBatch* pBatch)
    : m_pDatabase(std::make_unique<Database>(pDBWrapper, pBatch)) { }

CoinDB::~CoinDB() { }

std::unordered_map<mw::Hash, mw::UTXO::CPtr> CoinDB::GetUTXOs(const std::vector<mw::Hash>& output_ids) const
{
    std::unordered_map<mw::Hash, mw::UTXO::CPtr> utxos;

    for (const mw::Hash& output_id : output_ids) {
        auto pUTXO = m_pDatabase->Get<mw::UTXO>(UTXO_TABLE, output_id.ToHex());
        if (pUTXO != nullptr) {
            utxos.insert({output_id, pUTXO->item});
        }
    }

    return utxos;
}

void CoinDB::AddUTXOs(const std::vector<mw::UTXO::CPtr>& utxos)
{
    std::vector<DBEntry<mw::UTXO>> entries;
    std::transform(
        utxos.cbegin(), utxos.cend(),
        std::back_inserter(entries),
        [](const mw::UTXO::CPtr& pUTXO) { return DBEntry<mw::UTXO>(pUTXO->GetOutputID().ToHex(), pUTXO); }
    );

    m_pDatabase->Put(UTXO_TABLE, entries);
}

void CoinDB::RemoveUTXOs(const std::vector<mw::Hash>& output_ids)
{
    for (const mw::Hash& output_id : output_ids) {
        m_pDatabase->Delete(UTXO_TABLE, output_id.ToHex());
    }
}
