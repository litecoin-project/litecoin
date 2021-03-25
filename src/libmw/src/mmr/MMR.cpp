#include <mw/mmr/MMR.h>

using namespace mmr;

LeafIndex MMR::AddLeaf(std::vector<uint8_t>&& data)
{
    const LeafIndex leafIdx = m_pBackend->GetNextLeaf();
    m_pBackend->AddLeaf(Leaf::Create(leafIdx, std::move(data)));
    return leafIdx;
}

uint64_t MMR::GetNumLeaves() const noexcept
{
    return m_pBackend->GetNumLeaves();
}

uint64_t MMR::GetNumNodes() const noexcept
{
    const uint64_t numLeaves = m_pBackend->GetNumLeaves();
    if (numLeaves == 0)
    {
        return 0;
    }

    return LeafIndex::At(numLeaves).GetPosition();
}

void MMR::Rewind(const uint64_t numLeaves)
{
    LOG_TRACE_F("MMR: Rewinding to {}", numLeaves);
    m_pBackend->Rewind(LeafIndex::At(numLeaves));
}

void MMR::BatchWrite(
    const uint32_t file_index,
    const LeafIndex& firstLeafIdx,
    const std::vector<Leaf>& leaves,
    const std::unique_ptr<libmw::IDBBatch>& pBatch)
{
    LOG_TRACE_F("MMR: Writing batch {} with first leaf {}", file_index, firstLeafIdx.GetLeafIndex());

    m_pBackend->Rewind(firstLeafIdx);
    for (const Leaf& leaf : leaves)
    {
        m_pBackend->AddLeaf(leaf);
    }

    m_pBackend->Commit(file_index, pBatch);
}