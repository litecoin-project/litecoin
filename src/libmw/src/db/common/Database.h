#pragma once

#include "DBTable.h"
#include "DBTransaction.h"
#include "DBEntry.h"

#include <mw/file/FilePath.h>

#include <libmw/interfaces/db_interface.h>
#include <vector>
#include <cassert>
#include <memory>

class Database
{
public:
    using Ptr = std::shared_ptr<Database>;

    Database(libmw::IDBWrapper* pDatabase, libmw::IDBBatch* pBatch = nullptr)
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
        typename SFINAE = typename std::enable_if_t<std::is_base_of_v<Traits::ISerializable, T>>>
    std::unique_ptr<DBEntry<T>> Get(const DBTable& table, const std::string& key) const noexcept
    {
        if (m_pTx != nullptr)
        {
            return m_pTx->Get<T>(table, key);
        }

        std::vector<uint8_t> item;
        const bool status = m_pDB->Read(table.BuildKey(key), item);
        if (status)
        {
            Deserializer deserializer(std::move(item));
            return std::make_unique<DBEntry<T>>(key, T::Deserialize(deserializer));
        }

        return nullptr;
    }

    template<typename T,
        typename SFINAE = typename std::enable_if_t<std::is_base_of_v<Traits::ISerializable, T>>>
    void Put(const DBTable& table, const std::vector<DBEntry<T>>& entries)
    {
        assert(!entries.empty());

        if (m_pTx != nullptr)
        {
            m_pTx->Put(table, entries);
        }
        else
        {
            auto pBatch = m_pDB->CreateBatch();
            DBTransaction(m_pDB, pBatch.get()).Put(table, entries);
            pBatch->Commit();
        }
    }

    void Delete(const DBTable& table, const std::string& key)
    {
        if (m_pTx != nullptr)
        {
            m_pTx->Delete(table, key);
        }
        else
        {
            auto pBatch = m_pDB->CreateBatch();
            DBTransaction(m_pDB, pBatch.get()).Delete(table, key);
            pBatch->Commit();
        }
    }

    void DeleteAll(const DBTable& table)
    {
        auto pBatch = m_pDB->CreateBatch();

        auto iter = m_pDB->NewIterator();
        iter->Seek(std::to_string(table.GetPrefix()));
        while (iter->Valid()) {
            std::string key;
            if (iter->GetKey(key) && !key.empty() && key.front() == table.GetPrefix()) {
                pBatch->Erase(key);
                iter->Next();
            } else {
                break;
            }
        }

        pBatch->Commit();
    }

    libmw::IDBWrapper* m_pDB;
    DBTransaction::UPtr m_pTx;
};