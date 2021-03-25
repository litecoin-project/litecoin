#pragma once

#include <mw/mmr/Leaf.h>
#include <mw/models/crypto/Hash.h>
#include <libmw/interfaces/db_interface.h>

// Forward Declarations
class Database;

class LeafDB
{
public:
    LeafDB(const char prefix, libmw::IDBWrapper* pDBWrapper, libmw::IDBBatch* pBatch = nullptr);
    ~LeafDB();

    std::unique_ptr<mmr::Leaf> Get(const mmr::LeafIndex& idx) const;
    void Add(const std::vector<mmr::Leaf>& leaves);
    void Remove(const std::vector<mmr::LeafIndex>& indices);
    void RemoveAll();

private:
    char m_prefix;
    std::unique_ptr<Database> m_pDatabase;
};