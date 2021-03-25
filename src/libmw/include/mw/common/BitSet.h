#pragma once

#include <mw/traits/Serializable.h>
#include <mw/serialization/Serializer.h>
#include <boost/dynamic_bitset.hpp>
#include <vector>

struct BitSet : public Traits::ISerializable
{
    boost::dynamic_bitset<> bitset;

    BitSet() = default;
    BitSet(const size_t size)
        : bitset(size) { }

    static BitSet From(const std::vector<uint8_t>& bytes)
    {
        BitSet ret;
        ret.bitset.reserve(bytes.size() * 8);

        for (uint8_t byte : bytes) {
            for (uint8_t i = 0; i < 8; i++) {
                ret.bitset.push_back(byte & (0x80 >> i));
            }
        }

        return ret;
    }

    std::vector<uint8_t> bytes() const noexcept
    {
        std::vector<uint8_t> bytes((bitset.size() + 7) / 8);

        for (size_t i = 0; i < bytes.size(); i++) {
            for (uint8_t j = 0; j < 8; j++) {
                size_t bit_index = (i * 8) + j;
                if (bitset.size() > bit_index && bitset.test(bit_index)) {
                    bytes[i] |= (0x80 >> j);
                }
            }
        }

        return bytes;
    }

    std::string str() const noexcept
    {
        std::string val;
        boost::to_string(bitset, val);

        // Reverse for ascending order
        return std::string(val.crbegin(), val.crend());
    }

    bool test(uint64_t idx) const noexcept { return bitset.size() > idx && bitset.test(idx); }
    uint64_t count() const noexcept { return bitset.count(); }
    uint64_t size() const noexcept { return bitset.size(); }

    /// <summary>
    /// Calculates the number of set bits that are smaller or equal to idx.
    /// </summary>
    /// <param name="idx">The index to calculate the rank for.</param>
    /// <returns>The calculated rank.</returns>
    uint64_t rank(uint64_t idx) const noexcept
    {
        uint64_t rank = 0;
        for (uint64_t i = 0; i < idx; i++) {
            if (i >= size()) {
                break;
            }

            if (test(i)) {
                ++rank;
            }
        }

        return rank;
    }

    void set(size_t idx, bool val = true) noexcept { bitset.set(idx, val); }
    void set(size_t idx, size_t len, bool val) noexcept { bitset.set(idx, len, val); }
    void push_back(bool val) noexcept { bitset.push_back(val); }

    Serializer& Serialize(Serializer& serializer) const noexcept final
    {
        std::vector<uint8_t> vec = bytes();
        return serializer
            .Append<uint64_t>(vec.size())
            .Append(vec);
    }

    static BitSet Deserialize(Deserializer& deserializer)
    {
        uint64_t num_bytes = deserializer.Read<uint64_t>();
        return BitSet::From(deserializer.ReadVector(num_bytes));
    }
};