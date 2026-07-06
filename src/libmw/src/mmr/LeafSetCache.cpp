#include <mw/mmr/LeafSet.h>
#include <mw/crypto/Hasher.h>

using namespace mmr;

void LeafSetCache::ApplyUpdates(
    const uint32_t /*file_index*/,
    const mmr::LeafIndex& nextLeafIdx,
    const std::unordered_map<uint64_t, uint8_t>& modifiedBytes)
{
    m_nextLeafIdx = nextLeafIdx;

    for (auto byte : modifiedBytes) {
        m_modifiedBytes[byte.first] = byte.second;
    }
}

void LeafSetCache::Flush(const uint32_t file_index)
{
    m_pBacked->ApplyUpdates(file_index, m_nextLeafIdx, m_modifiedBytes);
    m_modifiedBytes.clear();
}

void LeafSetCache::ReadBytes(const uint64_t byteIdx, const uint64_t numBytes, std::vector<uint8_t>& out) const
{
    m_pBacked->ReadBytes(byteIdx, numBytes, out);
    if (numBytes == 0 || m_modifiedBytes.empty()) {
        return;
    }

    const uint64_t end = byteIdx + numBytes;
    for (const auto& entry : m_modifiedBytes) {
        if (entry.first >= byteIdx && entry.first < end) {
            out[static_cast<size_t>(entry.first - byteIdx)] = entry.second;
        }
    }
}

uint8_t LeafSetCache::GetByte(const uint64_t byteIdx) const
{
    auto iter = m_modifiedBytes.find(byteIdx);
    if (iter != m_modifiedBytes.cend())
    {
        return iter->second;
    }

    return m_pBacked->GetByte(byteIdx);
}

void LeafSetCache::SetByte(const uint64_t byteIdx, const uint8_t value)
{
    m_modifiedBytes[byteIdx] = value;
}
