#include <mw/mmr/LeafSet.h>
#include <mw/crypto/Hasher.h>

using namespace mmr;

void ILeafSet::Add(const LeafIndex& idx)
{
    uint8_t byte = GetByte(idx.Get() / 8);
    byte |= BitToByte(idx.Get() % 8);
    SetByte(idx.Get() / 8, byte);

    if (idx >= m_nextLeafIdx) {
        m_nextLeafIdx = idx.Next();
    }
}

void ILeafSet::Remove(const LeafIndex& idx)
{
    uint8_t byte = GetByte(idx.Get() / 8);
    byte &= (0xff ^ BitToByte(idx.Get() % 8));
    SetByte(idx.Get() / 8, byte);
}

bool ILeafSet::Contains(const LeafIndex& idx) const noexcept
{
    return GetByte(idx.Get() / 8) & BitToByte(idx.Get() % 8);
}

void ILeafSet::ReadBytes(const uint64_t byteIdx, const uint64_t numBytes, std::vector<uint8_t>& out) const
{
    out.resize(numBytes);
    for (uint64_t i = 0; i < numBytes; i++) {
        out[i] = GetByte(byteIdx + i);
    }
}

mw::Hash ILeafSet::Root() const
{
    uint64_t numBytes = (m_nextLeafIdx.Get() + 7) / 8;

    std::vector<uint8_t> bytes;
    ReadBytes(0, numBytes, bytes);

    return Hashed(bytes);
}

void ILeafSet::Rewind(const uint64_t numLeaves, const std::vector<LeafIndex>& leavesToAdd)
{
    for (const LeafIndex& idx : leavesToAdd) {
        Add(idx);
    }

    for (uint64_t i = numLeaves; i < m_nextLeafIdx.Get(); i++) {
        Remove(LeafIndex::At(i));
    }

    m_nextLeafIdx = mmr::LeafIndex::At(numLeaves);
}

// Returns a byte with the given bit (0-7) set.
// Example: BitToByte(2) returns 32 (00100000).
uint8_t ILeafSet::BitToByte(const uint8_t bit) const
{
    return 1 << (7 - bit);
}

BitSet ILeafSet::ToBitSet() const
{
    BitSet bitset(GetNextLeafIdx().Get());

    mmr::LeafIndex idx = mmr::LeafIndex::At(0);
    while (idx < GetNextLeafIdx()) {
        if (Contains(idx)) {
            bitset.set(idx.Get());
        }

        ++idx;
    }

    return bitset;
}
