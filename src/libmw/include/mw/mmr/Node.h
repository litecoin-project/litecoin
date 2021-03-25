#pragma once

// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <mw/common/Macros.h>
#include <mw/mmr/Index.h>
#include <mw/models/crypto/Hash.h>
#include <mw/crypto/Hasher.h>

MMR_NAMESPACE

class Node
{
public:
    static Node CreateParent(const Index& index, const mw::Hash& left_hash, const mw::Hash& right_hash)
    {
        return Node(index, CalcParentHash(index, left_hash, right_hash));
    }

    static mw::Hash CalcParentHash(const Index& index, const mw::Hash& left_hash, const mw::Hash& right_hash)
    {
        return Hasher()
            .Append<uint64_t>(index.GetPosition())
            .Append(left_hash)
            .Append(right_hash)
            .hash();
    }

    const Index& GetIndex() const noexcept { return m_index; }
    const mw::Hash& GetHash() const noexcept { return m_hash; }
    uint64_t GetHeight() const noexcept { return m_index.GetHeight(); }

private:
    Node(const Index& index, mw::Hash&& hash)
        : m_index(index), m_hash(std::move(hash)) { }

    Index m_index;
    mw::Hash m_hash;
};

END_NAMESPACE