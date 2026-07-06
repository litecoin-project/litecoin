#include <mw/mmr/LeafSet.h>
#include <mw/crypto/Hasher.h>

using namespace mmr;

LeafSet::Ptr LeafSet::Open(const FilePath& leafset_dir, const uint32_t file_index)
{
    File file = GetPath(leafset_dir, file_index);
    if (!file.Exists()) {
        file.Create();
    }

    mmr::LeafIndex nextLeafIdx = mmr::LeafIndex::At(0);
    if (file.GetSize() < 8) {
        file.Write(nextLeafIdx.Serialized());
        file.Commit();
    } else {
        nextLeafIdx = LeafIndex::Deserialize(file.ReadBytes(0, 8));
    }

    MemMap mappedFile{ file };
    mappedFile.Map();
    return std::shared_ptr<LeafSet>(new LeafSet{ leafset_dir, std::move(mappedFile), nextLeafIdx });
}

FilePath LeafSet::GetPath(const FilePath& leafset_dir, const uint32_t file_index)
{
    return leafset_dir.GetChild(StringUtil::Format("leaf{:0>6}.dat", file_index));
}

void LeafSet::ApplyUpdates(
    const uint32_t file_index,
    const mmr::LeafIndex& nextLeafIdx,
    const std::unordered_map<uint64_t, uint8_t>& modifiedBytes)
{
    for (auto byte : modifiedBytes) {
        m_modifiedBytes[byte.first + 8] = byte.second;
    }

    // In case of rewind, make sure to clear everything above the new next
    for (size_t idx = nextLeafIdx.Get(); idx < m_nextLeafIdx.Get(); idx++) {
        Remove(mmr::LeafIndex::At(idx));
    }

    m_nextLeafIdx = nextLeafIdx;

    Flush(file_index);
}

void LeafSet::Flush(const uint32_t file_index)
{
    std::vector<uint8_t> nextLeafIdxBytes = m_nextLeafIdx.Serialized();
    assert(nextLeafIdxBytes.size() == 8);

    for (uint8_t i = 0; i < 8; i++) {
        m_modifiedBytes[i] = nextLeafIdxBytes[i];
    }

    // Build, sync, and map the new leafset file before adopting it, so that a
    // failure at any step leaves this object consistent: still mapped to the
    // old (untouched) file, with m_modifiedBytes retained.
    m_mmap.Unmap();
    try {
        FilePath new_leafset_path = GetPath(m_dir, file_index);
        if (m_mmap.GetFile().GetPath().ToString() != new_leafset_path.ToString()) {
            m_mmap.GetFile().CopyTo(new_leafset_path);
        }

        File new_leafset_file(std::move(new_leafset_path));
        new_leafset_file.WriteBytes(m_modifiedBytes);
        new_leafset_file.Commit();

        MemMap new_mmap{ new_leafset_file };
        new_mmap.Map();
        m_mmap = std::move(new_mmap);
    } catch (...) {
        // All writes went to the new path; restore the old mapping so reads
        // remain valid, and let the caller treat the flush as fatal.
        m_mmap.Map();
        throw;
    }

    m_modifiedBytes.clear();
}

void LeafSet::Cleanup(const uint32_t current_file_index) const
{
    uint32_t file_index = current_file_index;
    while (file_index > 0) {
        FilePath prev_leafset = GetPath(m_dir, --file_index);
        if (prev_leafset.Exists()) {
            prev_leafset.Remove();
        } else {
            break;
        }
    }
}

void LeafSet::ReadBytes(const uint64_t byteIdx, const uint64_t numBytes, std::vector<uint8_t>& out) const
{
    out.assign(numBytes, 0);
    if (numBytes == 0) {
        return;
    }

    const uint64_t start = byteIdx + 8;
    const uint64_t map_size = static_cast<uint64_t>(m_mmap.size());
    if (start < map_size) {
        const uint64_t available = map_size - start;
        const uint64_t to_read = available < numBytes ? available : numBytes;
        std::vector<uint8_t> base = m_mmap.Read(static_cast<size_t>(start), static_cast<size_t>(to_read));
        for (size_t i = 0; i < base.size(); i++) {
            out[i] = base[i];
        }
    }

    if (!m_modifiedBytes.empty()) {
        const uint64_t end = start + numBytes;
        for (const auto& entry : m_modifiedBytes) {
            if (entry.first >= start && entry.first < end) {
                out[static_cast<size_t>(entry.first - start)] = entry.second;
            }
        }
    }
}

uint8_t LeafSet::GetByte(const uint64_t byteIdx) const
{
    // Offset by 8 bytes, since first 8 bytes in file represent the next leaf index
    const uint64_t byteIdxWithOffset = byteIdx + 8;

    auto iter = m_modifiedBytes.find(byteIdxWithOffset);
    if (iter != m_modifiedBytes.cend())
    {
        return iter->second;
    }
    else if (byteIdxWithOffset < m_mmap.size())
    {
        return m_mmap.ReadByte(byteIdxWithOffset);
    }

    return 0;
}

void LeafSet::SetByte(const uint64_t byteIdx, const uint8_t value)
{
    m_modifiedBytes[byteIdx + 8] = value;
}
