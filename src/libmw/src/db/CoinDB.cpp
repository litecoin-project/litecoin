#include <mw/db/CoinDB.h>
#include "common/Database.h"

static const DBTable COIN_TABLE = { 'U' };

CoinDB::CoinDB(CDBWrapper* pDBWrapper, CDBBatch* pBatch)
    : m_pDatabase(std::make_unique<Database>(pDBWrapper, pBatch)) { }

CoinDB::~CoinDB() { }

std::unordered_map<mw::Hash, mw::Coin::CPtr> CoinDB::GetCoins(const std::vector<mw::Hash>& output_ids) const
{
    std::unordered_map<mw::Hash, mw::Coin::CPtr> coins;

    for (const mw::Hash& output_id : output_ids) {
        auto pCoin = m_pDatabase->Get<mw::Coin>(COIN_TABLE, output_id.ToHex());
        if (pCoin != nullptr) {
            coins.insert({output_id, pCoin->item});
        }
    }

    return coins;
}

void CoinDB::AddCoins(const std::vector<mw::Coin::CPtr>& coins)
{
    std::vector<DBEntry<mw::Coin>> entries;
    std::transform(
        coins.cbegin(), coins.cend(),
        std::back_inserter(entries),
        [](const mw::Coin::CPtr& pCoin) { return DBEntry<mw::Coin>(pCoin->GetOutputID().ToHex(), pCoin); }
    );

    m_pDatabase->Put(COIN_TABLE, entries);
}

void CoinDB::RemoveCoins(const std::vector<mw::Hash>& output_ids)
{
    for (const mw::Hash& output_id : output_ids) {
        m_pDatabase->Delete(COIN_TABLE, output_id.ToHex());
    }
}
