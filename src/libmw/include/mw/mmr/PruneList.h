#pragma once

#include <mw/file/FilePath.h>
#include <mw/mmr/Index.h>
#include <mw/mmr/LeafIndex.h>
#include <mw/common/BitSet.h>
#include <memory>

class PruneList
{
public:
    using Ptr = std::shared_ptr<PruneList>;
    using CPtr = std::shared_ptr<const PruneList>;

    static PruneList::Ptr Open(const FilePath& parent_dir, const uint32_t file_index);
    static PruneList::Ptr Create(const FilePath& parent_dir);
    static FilePath GetPath(const FilePath& dir, const uint32_t file_index);

    uint64_t GetShift(const mmr::Index& index) const noexcept;
    uint64_t GetShift(const mmr::LeafIndex& index) const noexcept;
    uint64_t GetTotalShift() const noexcept { return m_totalShift; }
    const BitSet& GetCompacted() const noexcept { return m_compacted; }
    bool IsCompacted(const mmr::Index& index) const noexcept { return m_compacted.test(index.GetPosition()); }

    void Commit(const uint32_t file_index, const BitSet& compacted);

private:
    PruneList(const FilePath& dir, BitSet&& compacted, uint64_t total_shift)
        : m_dir(dir), m_compacted(std::move(compacted)), m_totalShift(total_shift) { BuildRanks(); }

    void BuildRanks();
    static constexpr uint64_t RANK_INTERVAL{256};

    FilePath m_dir;
    BitSet m_compacted;
    uint64_t m_totalShift;
    std::vector<uint64_t> m_ranks;
};
