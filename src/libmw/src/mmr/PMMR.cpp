#include <mw/mmr/MMR.h>
#include <mw/mmr/MMRUtil.h>
#include <mw/mmr/PruneList.h>
#include <mw/db/LeafDB.h>
#include <mw/exceptions/NotFoundException.h>

using namespace mmr;

PMMR::Ptr PMMR::Open(
    const char dbPrefix,
    const FilePath& mmr_dir,
    const uint32_t file_index,
    CDBWrapper* pDBWrapper,
    const PruneList::CPtr& pPruneList,
    const uint64_t minimum_leaves)
{
    auto pHashFile = AppendOnlyFile::Load(
        GetPath(mmr_dir, dbPrefix, file_index)
    );
    auto mmr = std::make_shared<PMMR>(
        dbPrefix,
        mmr_dir,
        pHashFile,
        pDBWrapper,
        pPruneList
    );
    if (pHashFile->GetSize() % mw::Hash::size() != 0) {
        ThrowFile_F("Invalid MWEB hash file size: {}", GetPath(mmr_dir, dbPrefix, file_index));
    }
    mmr->m_minimumLeaves = minimum_leaves;
    return mmr;
}

FilePath PMMR::GetPath(const FilePath& dir, const char prefix, const uint32_t file_index)
{
    return dir.GetChild(StringUtil::Format("{}{:0>6}.dat", prefix, file_index));
}

LeafIndex PMMR::AddLeaf(const mmr::Leaf& leaf)
{
    m_leafMap[leaf.GetLeafIndex()] = m_leaves.size();
    m_leaves.push_back(leaf);
    m_pHashFile->Append(leaf.GetHash().vec());

    auto rightHash = leaf.GetHash();
    auto nextIdx = leaf.GetNodeIndex().GetNext();
    while (!nextIdx.IsLeaf()) {
        const mw::Hash leftHash = GetHash(nextIdx.GetLeftChild());
        rightHash = MMRUtil::CalcParentHash(nextIdx, leftHash, rightHash);

        m_pHashFile->Append(rightHash.vec());
        nextIdx = nextIdx.GetNext();
    }

    return leaf.GetLeafIndex();
}

Leaf PMMR::GetLeaf(const LeafIndex& idx) const
{
    auto it = m_leafMap.find(idx);
    if (it != m_leafMap.end()) {
        return m_leaves[it->second];
    }

    LeafDB ldb(m_dbPrefix, m_pDatabase);
    auto pLeaf = ldb.Get(idx);
    if (!pLeaf) {
        ThrowNotFound_F("Can't get leaf at position {}", idx.GetPosition());
    }

    return std::move(*pLeaf);
}

mw::Hash PMMR::GetHash(const Index& idx) const
{
    uint64_t pos = idx.GetPosition();
    if (m_pPruneList) {
        if (m_pPruneList->IsCompacted(idx)) {
            ThrowNotFound_F("MMR hash at position {} has been compacted", pos);
        }

        pos -= m_pPruneList->GetShift(idx);
    }

    return mw::Hash(m_pHashFile->Read(pos * mw::Hash::size(), mw::Hash::size()));
}

uint64_t PMMR::GetNumLeaves() const noexcept
{
    uint64_t num_hashes = (m_pHashFile->GetSize() / mw::Hash::size());
    if (m_pPruneList) {
        num_hashes += m_pPruneList->GetTotalShift();
    }

    return Index::At(num_hashes).GetLeafIndex();
}

LeafIndex PMMR::GetNextLeafIdx() const noexcept
{
    return LeafIndex::At(GetNumLeaves());
}

uint64_t PMMR::GetNumNodes() const noexcept
{
    return LeafIndex::At(GetNumLeaves()).GetPosition();
}

void PMMR::Rewind(const uint64_t numLeaves)
{
    if (numLeaves < m_minimumLeaves) {
        throw std::runtime_error("Cannot rewind MWEB PMMR below the compaction horizon");
    }

    LeafIndex next_leaf_idx = LeafIndex::At(numLeaves);
    uint64_t pos = next_leaf_idx.GetPosition();
    if (m_pPruneList) {
        pos -= m_pPruneList->GetShift(next_leaf_idx);
    }

    m_pHashFile->Rewind(pos * mw::Hash::size());
}

PMMR::Ptr PMMR::Compact(const uint32_t file_index, const BitSet& compacted, const uint64_t minimum_leaves) const
{
    if (GetPath(m_dir, m_dbPrefix, file_index) == m_pHashFile->GetPath()) {
        throw std::runtime_error("MWEB compaction requires a new file generation");
    }

    if (!m_leaves.empty() || !m_leafMap.empty() || minimum_leaves < m_minimumLeaves || minimum_leaves > GetNumLeaves()) {
        throw std::runtime_error("MWEB compaction requires a flushed MMR and a forward horizon");
    }

    const BitSet empty;
    const BitSet& previous = m_pPruneList ? m_pPruneList->GetCompacted() : empty;
    const uint64_t horizon_nodes = LeafIndex::At(minimum_leaves).GetPosition();
    for (uint64_t pos = 0; pos < std::max(previous.size(), compacted.size()); ++pos) {
        if ((previous.test(pos) && !compacted.test(pos)) || (pos >= horizon_nodes && compacted.test(pos))) {
            throw std::runtime_error("Invalid MWEB compaction mask");
        }
    }

    auto prune = PruneList::Create(m_dir);
    prune->Commit(file_index, compacted);

    File output(GetPath(m_dir, m_dbPrefix, file_index));
    output.Write({}); // Truncate any orphan from an interrupted attempt.
    constexpr size_t CHUNK_SIZE{1024 * 1024};
    std::vector<uint8_t> retained;
    retained.reserve(CHUNK_SIZE);
    uint64_t logical = 0;
    size_t written = 0;
    for (uint64_t offset = 0; offset < m_pHashFile->GetSize();) {
        const auto bytes = m_pHashFile->Read(offset, std::min<uint64_t>(CHUNK_SIZE, m_pHashFile->GetSize() - offset));
        for (size_t i = 0; i < bytes.size(); i += mw::Hash::size()) {
            while (previous.test(logical)) ++logical;
            if (!compacted.test(logical)) {
                retained.insert(retained.end(), bytes.begin() + i, bytes.begin() + i + mw::Hash::size());
            }
            ++logical;
        }
        if (!retained.empty()) {
            output.Write(written, retained, false);
            written += retained.size();
            retained.clear();
        }
        offset += bytes.size();
    }
    output.Commit();

    auto result = Open(m_dbPrefix, m_dir, file_index, m_pDatabase, prune, minimum_leaves);
    if (result->GetNumLeaves() != GetNumLeaves() || result->Root() != Root()) {
        throw std::runtime_error("MWEB compaction changed the output MMR");
    }
    return result;
}

void PMMR::Adopt(PMMR& replacement) noexcept
{
    m_pHashFile.swap(replacement.m_pHashFile);
    m_pPruneList.swap(replacement.m_pPruneList);
    std::swap(m_minimumLeaves, replacement.m_minimumLeaves);
}

void PMMR::BatchWrite(
    const uint32_t file_index,
    const LeafIndex& firstLeafIdx,
    const std::vector<Leaf>& leaves,
    CDBBatch* pBatch)
{
    Rewind(firstLeafIdx.Get());
    for (const Leaf& leaf : leaves) {
        AddLeaf(leaf);
    }

    m_pHashFile->Commit(GetPath(m_dir, m_dbPrefix, file_index));

    // Update database
    LeafDB(m_dbPrefix, m_pDatabase, pBatch)
        .Add(m_leaves);

    m_leaves.clear();
    m_leafMap.clear();
}

void PMMR::Cleanup(const uint32_t current_file_index) const
{
    uint32_t file_index = current_file_index;
    while (file_index > 0) {
        FilePath prev_hashfile = GetPath(m_dir, m_dbPrefix, --file_index);
        if (prev_hashfile.Exists()) {
            prev_hashfile.Remove();
        } else {
            break;
        }
    }
}
