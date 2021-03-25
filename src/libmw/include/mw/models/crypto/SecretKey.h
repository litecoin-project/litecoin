#pragma once

// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <mw/models/crypto/BigInteger.h>
#include <mw/traits/Serializable.h>
#include <support/allocators/secure.h>

template<size_t NUM_BYTES>
class secret_key_t : public Traits::ISerializable
{
public:
    //
    // Constructor
    //
    secret_key_t() = default;
    secret_key_t(BigInt<NUM_BYTES>&& value) : m_value(std::move(value)) { }
    secret_key_t(const SecureVector& bytes) : m_value(BigInt<NUM_BYTES>(bytes.data())) { }
    secret_key_t(std::vector<uint8_t>&& bytes) : m_value(BigInt<NUM_BYTES>(std::move(bytes))) { }
    secret_key_t(const std::array<uint8_t, NUM_BYTES>& bytes) : m_value(BigInt<NUM_BYTES>(bytes)) {}
    secret_key_t(std::array<uint8_t, NUM_BYTES>&& bytes) : m_value(BigInt<NUM_BYTES>(std::move(bytes))) { }
    secret_key_t(const uint8_t* bytes) : m_value(BigInt<NUM_BYTES>(bytes)) { }

    //
    // Destructor
    //
    virtual ~secret_key_t() = default;

    //
    // Operators
    //
    bool operator==(const secret_key_t<NUM_BYTES>& rhs) const noexcept { return m_value == rhs.m_value; }

    //
    // Getters
    //
    const BigInt<NUM_BYTES>& GetBigInt() const { return m_value; }
    const std::vector<uint8_t>& vec() const { return m_value.vec(); }
    std::array<uint8_t, 32> array() const noexcept { return m_value.ToArray(); }
    uint8_t* data() { return m_value.data(); }
    const uint8_t* data() const { return m_value.data(); }
    uint8_t& operator[] (const size_t x) { return m_value[x]; }
    const uint8_t& operator[] (const size_t x) const { return m_value[x]; }
    size_t size() const { return m_value.size(); }

    //
    // Serialization/Deserialization
    //
    Serializer& Serialize(Serializer& serializer) const noexcept final
    {
        return m_value.Serialize(serializer);
    }

    static secret_key_t<NUM_BYTES> Deserialize(Deserializer& deserializer)
    {
        return secret_key_t<NUM_BYTES>(BigInt<NUM_BYTES>::Deserialize(deserializer));
    }

private:
    BigInt<NUM_BYTES> m_value;
};

using SecretKey = secret_key_t<32>;
using SecretKey64 = secret_key_t<64>;