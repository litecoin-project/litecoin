#pragma once

// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <mw/common/Macros.h>
#include <mw/mmr/Index.h>
#include <mw/util/BitUtil.h>

MMR_NAMESPACE

class LeafIndex
{
public:
    LeafIndex() noexcept
        : m_leafIndex(0), m_nodeIndex(0, 0) { }
    LeafIndex(const uint64_t leafIndex, const uint64_t position)
        : m_leafIndex(leafIndex), m_nodeIndex(position, 0) { }
    virtual ~LeafIndex() = default;

    static LeafIndex At(const uint64_t leafIndex) noexcept
    {
        return LeafIndex(leafIndex, (2 * leafIndex) - BitUtil::CountBitsSet(leafIndex));
    }

    bool operator<(const LeafIndex& rhs) const noexcept { return m_leafIndex < rhs.m_leafIndex; }
    bool operator>(const LeafIndex& rhs) const noexcept { return m_leafIndex > rhs.m_leafIndex; }
    bool operator==(const LeafIndex& rhs) const noexcept { return m_leafIndex == rhs.m_leafIndex; }
    bool operator!=(const LeafIndex& rhs) const noexcept { return m_leafIndex != rhs.m_leafIndex; }
    bool operator<=(const LeafIndex& rhs) const noexcept { return m_leafIndex <= rhs.m_leafIndex; }
    bool operator>=(const LeafIndex& rhs) const noexcept { return m_leafIndex >= rhs.m_leafIndex; }

    LeafIndex& operator++()
    {
        *this = this->Next();
        return *this;
    }

    uint64_t Get() const noexcept { return m_leafIndex; }
    uint64_t GetLeafIndex() const noexcept { return m_leafIndex; }
    const Index& GetNodeIndex() const noexcept { return m_nodeIndex; }
    uint64_t GetPosition() const noexcept { return m_nodeIndex.GetPosition(); }
    LeafIndex Next() const noexcept { return LeafIndex::At(m_leafIndex + 1); }

private:
    uint64_t m_leafIndex;
    Index m_nodeIndex;
};

END_NAMESPACE