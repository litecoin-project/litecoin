#pragma once

#include "DBTable.h"
#include "DBTransaction.h"
#include "DBEntry.h"

#include <dbwrapper.h>
#include <vector>
#include <cassert>
#include <memory>

class Database
{
public:
    using Ptr = std::shared_ptr<Database>;

    Database(CDBWrapper* pDatabase, CDBBatch* pBatch = nullptr)
        : m_pDB(pDatabase), m_pTx(nullptr)
    {
        if (pBatch != nullptr) {
            m_pTx = std::make_unique<DBTransaction>(pDatabase, pBatch);
        }
    }

    //
    // Operations
    //
    template<typename T,
        typename SFINAE = typename std::enable_if_t<std::is_base_of<Traits::ISerializable, T>::value>>
    std::unique_ptr<DBEntry<T>> Get(const DBTable& table, const std::string& key) const noexcept
    {
        if (!m_pDB) return nullptr;

        if (m_pTx != nullptr) {
            return m_pTx->Get<T>(table, key);
        }

        T item;
        const bool status = m_pDB->Read(table.BuildKey(key), item);
        if (status) {
            return std::make_unique<DBEntry<T>>(key, std::move(item));
        }

        return nullptr;
    }

    template<typename T,
        typename SFINAE = typename std::enable_if_t<std::is_base_of<Traits::ISerializable, T>::value>>
    void Put(const DBTable& table, const std::vector<DBEntry<T>>& entries)
    {
        assert(!entries.empty());

        if (m_pTx != nullptr) {
            m_pTx->Put(table, entries);
        } else {
            CDBBatch batch(*m_pDB);
            DBTransaction(m_pDB, &batch).Put(table, entries);
            m_pDB->WriteBatch(batch);
        }
    }

    void Delete(const DBTable& table, const std::string& key)
    {
        if (m_pTx != nullptr) {
            m_pTx->Delete(table, key);
        } else {
            CDBBatch batch(*m_pDB);
            DBTransaction(m_pDB, &batch).Delete(table, key);
            m_pDB->WriteBatch(batch);
        }
    }

private:
    CDBWrapper* m_pDB;
    DBTransaction::UPtr m_pTx;
};
