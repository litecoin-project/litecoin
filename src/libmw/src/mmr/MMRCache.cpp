#include <mw/mmr/MMR.h>

using namespace mmr;

LeafIndex MMRCache::AddLeaf(std::vector<uint8_t>&& data)
{
    LeafIndex leafIdx = LeafIndex::At(m_firstLeaf.GetLeafIndex() + m_leaves.size());
    Leaf leaf = Leaf::Create(leafIdx, std::move(data));

    m_nodes.push_back(leaf.GetHash());

    auto rightHash = leaf.GetHash();
    auto nextIdx = leaf.GetNodeIndex().GetNext();
    while (!nextIdx.IsLeaf()) {
        const mw::Hash leftHash = GetHash(nextIdx.GetLeftChild());
        const Node node = Node::CreateParent(nextIdx, leftHash, rightHash);

        m_nodes.push_back(node.GetHash());
        rightHash = node.GetHash();
        nextIdx = nextIdx.GetNext();
    }

    m_leaves.push_back(std::move(leaf));
    return leafIdx;
}

Leaf MMRCache::GetLeaf(const LeafIndex& leafIdx) const
{
    if (leafIdx < m_firstLeaf) {
        return m_pBase->GetLeaf(leafIdx);
    }

    const uint64_t cacheIdx = leafIdx.GetLeafIndex() - m_firstLeaf.GetLeafIndex();
    if (cacheIdx > m_leaves.size()) {
        throw std::out_of_range("Attempting to access non-existent leaf");
    }

    return m_leaves[cacheIdx];
}

LeafIndex MMRCache::GetNextLeafIdx() const noexcept
{
    if (m_leaves.empty()) {
        return m_firstLeaf;
    } else {
        return m_leaves.back().GetLeafIndex().Next();
    }
}

mw::Hash MMRCache::GetHash(const Index& idx) const
{
    if (idx < m_firstLeaf.GetPosition()) {
        return m_pBase->GetHash(idx);
    } else {
        const uint64_t vecIdx = idx.GetPosition() - m_firstLeaf.GetPosition();
        assert(m_nodes.size() > vecIdx);
        return m_nodes[vecIdx];
    }
}

void MMRCache::Rewind(const uint64_t numLeaves)
{
    LOG_TRACE_F("MMRCache: Rewinding to {}", numLeaves);

    LeafIndex nextLeaf = LeafIndex::At(numLeaves);
    if (nextLeaf <= m_firstLeaf) {
        m_firstLeaf = nextLeaf;
        m_leaves.clear();
        m_nodes.clear();
    } else if (!m_leaves.empty()) {
        auto iter = m_leaves.begin();
        while (iter != m_leaves.end() && iter->GetLeafIndex() < nextLeaf) {
            iter++;
        }

        if (iter != m_leaves.end()) {
            m_leaves.erase(iter, m_leaves.end());
        }

        const uint64_t numNodes = GetNextLeafIdx().GetPosition() - m_firstLeaf.GetPosition();
        if (m_nodes.size() > numNodes) {
            m_nodes.erase(m_nodes.begin() + numNodes, m_nodes.end());
        }
    }
}

void MMRCache::BatchWrite(
    const uint32_t /*index*/,
    const LeafIndex& firstLeafIdx,
    const std::vector<Leaf>& leaves,
    const std::unique_ptr<libmw::IDBBatch>&)
{
    LOG_TRACE_F("MMRCache: Writing batch {}", firstLeafIdx.GetLeafIndex());
    Rewind(firstLeafIdx.GetLeafIndex());
    for (const Leaf& leaf : leaves) {
        Add(leaf.vec());
    }
}

void MMRCache::Flush(const uint32_t file_index, const std::unique_ptr<libmw::IDBBatch>& pBatch)
{
    LOG_TRACE_F(
        "MMRCache: Flushing {} leaves at {} with file index {}",
        m_leaves.size(),
        m_firstLeaf.GetLeafIndex(),
        file_index
    );
    m_pBase->BatchWrite(file_index, m_firstLeaf, m_leaves, pBatch);
    m_firstLeaf = GetNextLeafIdx();
    m_leaves.clear();
    m_nodes.clear();
}