#include <mw/mmr/backends/FileBackend.h>
#include <mw/mmr/Node.h>
#include <mw/db/LeafDB.h>
#include <mw/exceptions/NotFoundException.h>

std::shared_ptr<mmr::FileBackend> mmr::FileBackend::Open(
    const char dbPrefix,
    const FilePath& mmr_dir,
    const uint32_t file_index,
    const std::shared_ptr<libmw::IDBWrapper>& pDBWrapper,
    const mmr::PruneList::CPtr& pPruneList)
{
    const FilePath path = GetPath(mmr_dir, dbPrefix, file_index);
    return std::make_shared<FileBackend>(
        dbPrefix,
        mmr_dir,
        AppendOnlyFile::Load(path),
        pDBWrapper,
        pPruneList
    );
}

mmr::FileBackend::FileBackend(
    const char dbPrefix,
    const FilePath& mmr_dir,
    const AppendOnlyFile::Ptr& pHashFile,
    const std::shared_ptr<libmw::IDBWrapper>& pDBWrapper,
    const mmr::PruneList::CPtr& pPruneList)
    : m_dbPrefix(dbPrefix), m_dir(mmr_dir), m_pHashFile(pHashFile), m_pDatabase(pDBWrapper), m_pPruneList(pPruneList)
{
}

void mmr::FileBackend::AddLeaf(const Leaf& leaf)
{
    m_leafMap[leaf.GetLeafIndex()] = m_leaves.size();
    m_leaves.push_back(leaf);
    AddHash(leaf.GetHash());

    auto rightHash = leaf.GetHash();
    auto nextIdx = leaf.GetNodeIndex().GetNext();
    while (!nextIdx.IsLeaf()) {
        const mw::Hash leftHash = GetHash(nextIdx.GetLeftChild());
        const Node node = Node::CreateParent(nextIdx, leftHash, rightHash);

        AddHash(node.GetHash());
        rightHash = node.GetHash();
        nextIdx = nextIdx.GetNext();
    }
}

void mmr::FileBackend::AddHash(const mw::Hash& hash)
{
    m_pHashFile->Append(hash.vec());
}

void mmr::FileBackend::Rewind(const LeafIndex& nextLeafIndex)
{
    uint64_t pos = nextLeafIndex.GetPosition();
    if (m_pPruneList) {
        pos -= m_pPruneList->GetShift(nextLeafIndex);
    }

    m_pHashFile->Rewind(pos * 32);
}

void mmr::FileBackend::Compact(const uint32_t file_index, const boost::dynamic_bitset<uint64_t>& hashes_to_remove)
{
    uint64_t num_hashes = m_pHashFile->GetSize() / mw::Hash::size();
    assert(num_hashes = hashes_to_remove.size());

    const FilePath path = GetPath(filesystem::temp_directory_path(), m_dbPrefix, file_index);
    AppendOnlyFile::Ptr pFile = AppendOnlyFile::Load(path);

    for (uint64_t pos = 0; pos < hashes_to_remove.size(); pos++) {
        if (hashes_to_remove.test(pos)) {
            continue;
        }

        pFile->Append(m_pHashFile->Read(pos * mw::Hash::size(), mw::Hash::size()));
    }

    pFile->Commit(GetPath(m_dir, m_dbPrefix, file_index));
    m_pHashFile = pFile;
}

uint64_t mmr::FileBackend::GetNumLeaves() const noexcept
{
    uint64_t num_hashes = (m_pHashFile->GetSize() / mw::Hash::size());
    if (m_pPruneList) {
        num_hashes += m_pPruneList->GetTotalShift();
    }

    return Index::At(num_hashes).GetLeafIndex();
}

mw::Hash mmr::FileBackend::GetHash(const Index& idx) const
{
    uint64_t pos = idx.GetPosition();
    if (m_pPruneList) {
        pos -= m_pPruneList->GetShift(idx);
    }

    return mw::Hash(m_pHashFile->Read(pos * mw::Hash::size(), mw::Hash::size()));
}

mmr::Leaf mmr::FileBackend::GetLeaf(const LeafIndex& idx) const
{
    auto it = m_leafMap.find(idx);
    if (it != m_leafMap.end()) {
        return m_leaves[it->second];
    }

    LeafDB ldb(m_dbPrefix, m_pDatabase.get());
    auto pLeaf = ldb.Get(idx);
    if (!pLeaf) {
        ThrowNotFound_F("Can't get leaf at position {}", idx.GetPosition());
    }

    return std::move(*pLeaf);
}

void mmr::FileBackend::Commit(const uint32_t file_index, const std::unique_ptr<libmw::IDBBatch>& pBatch)
{
    m_pHashFile->Commit(GetPath(m_dir, m_dbPrefix, file_index));

    // Update database
    LeafDB(m_dbPrefix, m_pDatabase.get(), pBatch.get())
        .Add(m_leaves);

    m_leaves.clear();
    m_leafMap.clear();
}

FilePath mmr::FileBackend::GetPath(const FilePath& dir, const char prefix, const uint32_t file_index)
{
    return dir.GetChild(StringUtil::Format("{}{:0>6}.dat", prefix, file_index));;
}