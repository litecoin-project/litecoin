#pragma once

#include "DBTable.h"
#include "DBEntry.h"
#include "OrderedMultimap.h"

#include <mw/exceptions/DatabaseException.h>
#include <mw/serialization/Serializer.h>
#include <mw/traits/Serializable.h>
#include <libmw/interfaces/db_interface.h>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>

class DBTransaction
{
public:
    using UPtr = std::unique_ptr<DBTransaction>;

    DBTransaction(libmw::IDBWrapper* pDB, libmw::IDBBatch* pBatch)
        : m_pDB(pDB), m_pBatch(pBatch) { }

    template<typename T,
        typename SFINAE = typename std::enable_if_t<std::is_base_of_v<Traits::ISerializable, T>>>
    DBTransaction& Put(const DBTable& table, const std::vector<DBEntry<T>>& entries)
    {
        for (const auto& entry : entries)
        {
            const std::string key = table.BuildKey(entry);

            Serializer serializer;
            serializer.Append(entry.item);

            m_pBatch->Write(key, serializer.vec());
            m_added.insert({ key, entry.item });
        }

        return *this;
    }

    template<typename T,
        typename SFINAE = typename std::enable_if_t<std::is_base_of_v<Traits::ISerializable, T>>>
    std::unique_ptr<DBEntry<T>> Get(const DBTable& table, const std::string& key) const noexcept
    {
        auto iter = m_added.find_last(table.BuildKey(key));
        if (iter != nullptr)
        {
            auto pObject = std::dynamic_pointer_cast<const T>(iter);
            if (pObject != nullptr)
            {
                return std::make_unique<DBEntry<T>>(key, pObject);
            }
        }

        std::vector<uint8_t> entry;
        const bool status = m_pDB->Read(table.BuildKey(key), entry);
        if (status)
        {
            Deserializer deserializer(std::move(entry));
            return std::make_unique<DBEntry<T>>(key, T::Deserialize(deserializer));
        }

        return nullptr;
    }

    void Delete(const DBTable& table, const std::string& key)
    {
        m_pBatch->Erase(table.BuildKey(key));
        m_added.erase(table.BuildKey(key));
    }

private:
    libmw::IDBWrapper* m_pDB;
    libmw::IDBBatch* m_pBatch;
    OrderedMultimap<std::string, Traits::ISerializable> m_added;
};