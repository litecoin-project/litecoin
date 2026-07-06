#pragma once

#include <dbwrapper.h>
#include <mw/mmr/Leaf.h>
#include <mw/models/crypto/Hash.h>

// Forward Declarations
class Database;

class LeafDB
{
public:
    LeafDB(const char prefix, CDBWrapper* pDBWrapper, CDBBatch* pBatch = nullptr);
    ~LeafDB();

    std::unique_ptr<mmr::Leaf> Get(const mmr::LeafIndex& idx) const;
    void Add(const std::vector<mmr::Leaf>& leaves);
    void Remove(const std::vector<mmr::LeafIndex>& indices);

private:
    char m_prefix;
    std::unique_ptr<Database> m_pDatabase;
};
