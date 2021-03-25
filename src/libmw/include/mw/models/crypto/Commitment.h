#pragma once

// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <mw/models/crypto/BigInteger.h>
#include <mw/traits/Printable.h>
#include <mw/traits/Serializable.h>

#include <boost/container_hash/hash.hpp>
#include <cassert>

// Forward Declarations
class BlindingFactor;

class Commitment :
    public Traits::IPrintable,
    public Traits::ISerializable
{
public:
    static constexpr size_t const& SIZE = 33;

    //
    // Constructors
    //
    Commitment() = default;
    Commitment(BigInt<SIZE>&& bytes) : m_bytes(std::move(bytes)) { }
    Commitment(const BigInt<SIZE>& bytes) : m_bytes(bytes) { }
    Commitment(const std::array<uint8_t, SIZE>& bytes) : m_bytes(bytes) { }
    Commitment(const Commitment& other) = default;
    Commitment(Commitment&& other) noexcept = default;

    //
    // Destructor
    //
    virtual ~Commitment() = default;

    //
    // Factories
    //
    static Commitment Switch(const BlindingFactor& blind, const uint64_t value);
    static Commitment Blinded(const BlindingFactor& blind, const uint64_t value);
    static Commitment Transparent(const uint64_t value);

    //
    // Operators
    //
    Commitment& operator=(const Commitment& other) = default;
    Commitment& operator=(Commitment&& other) noexcept = default;
    bool operator<(const Commitment& rhs) const noexcept { return m_bytes < rhs.GetBigInt(); }
    bool operator!=(const Commitment& rhs) const noexcept { return m_bytes != rhs.GetBigInt(); }
    bool operator==(const Commitment& rhs) const noexcept { return m_bytes == rhs.GetBigInt(); }

    //
    // Getters
    //
    const BigInt<SIZE>& GetBigInt() const noexcept { return m_bytes; }
    const std::vector<uint8_t>& vec() const noexcept { return m_bytes.vec(); }
    std::array<uint8_t, 33> array() const noexcept { return m_bytes.ToArray(); }
    const uint8_t* data() const noexcept { return m_bytes.data(); }
    uint8_t* data() noexcept { return m_bytes.data(); }
    size_t size() const noexcept { return m_bytes.size(); }
    bool IsZero() const noexcept { return m_bytes.IsZero(); }

    //
    // Serialization/Deserialization
    //
    Serializer& Serialize(Serializer& serializer) const noexcept final;
    static Commitment Deserialize(Deserializer& deserializer);

    std::string ToHex() const { return m_bytes.ToHex(); }
    static Commitment FromHex(const std::string& hex) { return Commitment(BigInt<SIZE>::FromHex(hex)); }

    //
    // Traits
    //
    std::string Format() const final { return m_bytes.Format(); }

private:
    BigInt<SIZE> m_bytes;
};

namespace std
{
    template<>
    struct hash<Commitment>
    {
        size_t operator()(const Commitment& commitment) const
        {
            return boost::hash_value(commitment.vec());
        }
    };
}