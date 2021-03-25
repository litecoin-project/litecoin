#pragma once

// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <mw/common/Macros.h>
#include <mw/mmr/Backend.h>
#include <mw/mmr/Node.h>
#include <cassert>
#include <vector>

MMR_NAMESPACE

class VectorBackend : public IBackend
{
public:
    VectorBackend() { }

    void AddLeaf(const Leaf& leaf) final
    {
        m_leaves.push_back(leaf);
        AddHash(leaf.GetHash());

        auto rightHash = leaf.GetHash();
        auto nextIdx = leaf.GetNodeIndex().GetNext();
        while (!nextIdx.IsLeaf())
        {
            const mw::Hash leftHash = GetHash(nextIdx.GetLeftChild());
            const Node node = Node::CreateParent(nextIdx, leftHash, rightHash);

            AddHash(node.GetHash());
            rightHash = node.GetHash();
            nextIdx = nextIdx.GetNext();
        }
    }

    void AddHash(const mw::Hash& hash) final { m_nodes.push_back(hash); }
    void Rewind(const LeafIndex& nextLeafIndex) final
    {
        m_leaves.resize(nextLeafIndex.GetLeafIndex());
        m_nodes.resize(nextLeafIndex.GetPosition());
    }

    void Compact(const uint32_t, const boost::dynamic_bitset<uint64_t>&) final { }

    uint64_t GetNumLeaves() const noexcept final { return m_leaves.size(); }

    mw::Hash GetHash(const Index& idx) const final { return m_nodes[idx.GetPosition()]; }
    Leaf GetLeaf(const LeafIndex& idx) const final { return m_leaves[idx.GetLeafIndex()]; }

    // Not supported yet
    void Commit(const uint32_t index, const std::unique_ptr<libmw::IDBBatch>& pBatch) final { }

private:
    std::vector<Leaf> m_leaves;
    std::vector<mw::Hash> m_nodes;
};

END_NAMESPACE