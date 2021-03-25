#include <mw/db/CoinDB.h>
#include "common/Database.h"

static const DBTable UTXO_TABLE = { 'U', DBTable::Options({ false /* allowDuplicates */ }) };

CoinDB::CoinDB(libmw::IDBWrapper* pDBWrapper, libmw::IDBBatch* pBatch)
    : m_pDatabase(std::make_unique<Database>(pDBWrapper, pBatch)) { }

CoinDB::~CoinDB() { }

std::unordered_map<Commitment, UTXO::CPtr> CoinDB::GetUTXOs(const std::vector<Commitment>& commitments) const
{
    std::unordered_map<Commitment, UTXO::CPtr> utxos;

    for (const Commitment& commitment : commitments)
    {
        auto pUTXO = m_pDatabase->Get<UTXO>(UTXO_TABLE, commitment.ToHex());
        if (pUTXO != nullptr) {
            utxos.insert({ commitment, pUTXO->item });
        }
    }

    return utxos;
}

void CoinDB::AddUTXOs(const std::vector<UTXO::CPtr>& utxos)
{
    std::vector<DBEntry<UTXO>> entries;
    std::transform(
        utxos.cbegin(), utxos.cend(),
        std::back_inserter(entries),
        [](const UTXO::CPtr& pUTXO) { return DBEntry<UTXO>(pUTXO->GetCommitment().ToHex(), pUTXO); }
    );

    m_pDatabase->Put(UTXO_TABLE, entries);
}

void CoinDB::RemoveUTXOs(const std::vector<Commitment>& commitments)
{
    for (const Commitment& commitment : commitments)
    {
        m_pDatabase->Delete(UTXO_TABLE, commitment.ToHex());
    }
}

void CoinDB::RemoveAllUTXOs()
{
    m_pDatabase->DeleteAll(UTXO_TABLE);
}