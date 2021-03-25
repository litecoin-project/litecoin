#pragma once

// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <mw/traits/Printable.h>
#include <mw/traits/Serializable.h>
#include <mw/serialization/Serializer.h>
#include <mw/util/HexUtil.h>

#include <cassert>
#include <cstdint>
#include <vector>

class RangeProof :
    public Traits::IPrintable,
    public Traits::ISerializable
{
public:
    using CPtr = std::shared_ptr<const RangeProof>;
    static constexpr size_t const& MAX_SIZE = 675;

    //
    // Constructors
    //
    RangeProof() = default;
    RangeProof(std::vector<uint8_t>&& bytes) : m_bytes(std::move(bytes)) { assert(m_bytes.size() <= MAX_SIZE); }
    RangeProof(const RangeProof& other) = default;
    RangeProof(RangeProof&& other) noexcept = default;

    //
    // Destructor
    //
    virtual ~RangeProof() = default;

    //
    // Operators
    //
    RangeProof& operator=(const RangeProof& other) = default;
    RangeProof& operator=(RangeProof&& other) noexcept = default;
    bool operator==(const RangeProof& other) const noexcept { return m_bytes == other.m_bytes; }

    //
    // Getters
    //
    const std::vector<uint8_t>& vec() const { return m_bytes; }
    const uint8_t* data() const { return m_bytes.data(); }
    size_t size() const { return m_bytes.size(); }

    //
    // Serialization/Deserialization
    //
    Serializer& Serialize(Serializer& serializer) const noexcept final
    {
        return serializer
            .Append<uint16_t>((uint16_t)m_bytes.size())
            .Append(m_bytes);
    }

    static RangeProof Deserialize(Deserializer& deserializer)
    {
        const uint16_t proofSize = deserializer.Read<uint16_t>();
        if (proofSize > MAX_SIZE) {
            ThrowDeserialization("RangeProof is larger than MAX_SIZE");
        }

        return RangeProof(deserializer.ReadVector(proofSize));
    }

    std::string ToHex() const { return HexUtil::ToHex(m_bytes); }
    static RangeProof FromHex(const std::string& hex) { return RangeProof(HexUtil::FromHex(hex)); }

    //
    // Traits
    //
    std::string Format() const final { return HexUtil::ToHex(m_bytes); }

private:
    // The proof itself, at most 675 bytes long.
    std::vector<uint8_t> m_bytes;
};
