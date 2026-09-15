#include <mw/mmr/PruneList.h>
#include <mw/file/File.h>

using namespace mmr;

PruneList::Ptr PruneList::Open(const FilePath& parent_dir, const uint32_t file_index)
{
    File file = GetPath(parent_dir, file_index);

    BitSet bitset;
    if (file.Exists()) {
        bitset = BitSet::From(file.ReadBytes());
    } else if (file_index != 0) {
        ThrowFile_F("Missing MWEB prune list {}", file);
    }

    uint64_t total_shift = bitset.count();
    return std::shared_ptr<PruneList>(new PruneList(parent_dir, std::move(bitset), total_shift));
}

PruneList::Ptr PruneList::Create(const FilePath& parent_dir)
{
    return std::shared_ptr<PruneList>(new PruneList(parent_dir, BitSet{}, 0));
}

void PruneList::BuildRanks()
{
    m_ranks.clear();
    m_ranks.reserve((m_compacted.size() + RANK_INTERVAL - 1) / RANK_INTERVAL);
    uint64_t rank = 0;
    for (uint64_t i = 0; i < m_compacted.size(); ++i) {
        if (i % RANK_INTERVAL == 0) {
            m_ranks.push_back(rank);
        }

        if (m_compacted.test(i)) {
            ++rank;
        }
    }
}

FilePath PruneList::GetPath(const FilePath& dir, const uint32_t file_index)
{
    return dir.GetChild(StringUtil::Format("prun{:0>6}.dat", file_index));
}

uint64_t PruneList::GetShift(const Index& index) const noexcept
{
    assert(!m_compacted.test(index.GetPosition()));

    const uint64_t pos = index.GetPosition();
    if (pos >= m_compacted.size()) {
        return m_totalShift;
    }

    uint64_t rank = m_ranks[pos / RANK_INTERVAL];
    for (uint64_t i = pos - pos % RANK_INTERVAL; i < pos; ++i) {
        if (m_compacted.test(i)) {
            ++rank;
        }
    }

    return rank;
}

uint64_t PruneList::GetShift(const LeafIndex& index) const noexcept
{
    return GetShift(index.GetNodeIndex());
}

void PruneList::Commit(const uint32_t file_index, const BitSet& compacted)
{
    File file(GetPath(m_dir, file_index));
    file.Write(compacted.bytes());
    file.Commit();

    m_compacted = compacted;
    m_totalShift = compacted.count();
    BuildRanks();
}
