#pragma once

#include "DBTable.h"
#include "DBEntry.h"
#include "OrderedMultimap.h"

#include <dbwrapper.h>
#include <mw/common/Traits.h>
#include <mw/exceptions/DatabaseException.h>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>

class DBTransaction
{
public:
    using UPtr = std::unique_ptr<DBTransaction>;

    DBTransaction(CDBWrapper* pDB, CDBBatch* pBatch)
        : m_pDB(pDB), m_pBatch(pBatch) { }

    template<typename T,
        typename SFINAE = typename std::enable_if_t<std::is_base_of<Traits::ISerializable, T>::value>>
    DBTransaction& Put(const DBTable& table, const std::vector<DBEntry<T>>& entries)
    {
        for (const auto& entry : entries) {
            const std::string key = table.BuildKey(entry);

            m_pBatch->Write(key, *entry.item);
            m_added.insert({ key, entry.item });
        }

        return *this;
    }

    template<typename T,
        typename SFINAE = typename std::enable_if_t<std::is_base_of<Traits::ISerializable, T>::value>>
    std::unique_ptr<DBEntry<T>> Get(const DBTable& table, const std::string& key) const noexcept
    {
        auto table_key = table.BuildKey(key);
        auto iter = m_added.find_last(table_key);
        if (iter != nullptr) {
            auto pObject = std::dynamic_pointer_cast<const T>(iter);
            if (pObject != nullptr) {
                return std::make_unique<DBEntry<T>>(key, pObject);
            }
        }

        T item;
        const bool status = m_pDB->Read(table_key, item);
        if (status) {
            return std::make_unique<DBEntry<T>>(key, std::move(item));
        }

        return nullptr;
    }

    void Delete(const DBTable& table, const std::string& key)
    {
        auto table_key = table.BuildKey(key);
        m_pBatch->Erase(table_key);
        m_added.erase(table_key);
    }

private:
    CDBWrapper* m_pDB;
    CDBBatch* m_pBatch;
    OrderedMultimap<std::string, Traits::ISerializable> m_added;
};
