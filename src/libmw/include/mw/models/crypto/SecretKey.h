#pragma once

// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <mw/common/Traits.h>
#include <mw/models/crypto/BigInteger.h>
#include <mw/models/crypto/Hash.h>
#include <crypto/blake3/blake3.h>
#include <random.h>

template<size_t NUM_BYTES>
class secret_key_t : public Traits::ISerializable
{
public:
    //
    // Constructor
    //
    secret_key_t() = default;
    secret_key_t(BigInt<NUM_BYTES>&& value) : m_value(std::move(value)) {}
    secret_key_t(const BigInt<NUM_BYTES>& value) : m_value(value) {}
    secret_key_t(std::vector<uint8_t>&& bytes) : m_value(BigInt<NUM_BYTES>(std::move(bytes))) { }
    secret_key_t(const std::array<uint8_t, NUM_BYTES>& bytes) : m_value(BigInt<NUM_BYTES>(bytes)) {}
    secret_key_t(std::array<uint8_t, NUM_BYTES>&& bytes) : m_value(BigInt<NUM_BYTES>(std::move(bytes))) { }
    secret_key_t(const uint8_t* bytes) : m_value(BigInt<NUM_BYTES>(bytes)) { }
    secret_key_t(const secret_key_t& other) = default;
    secret_key_t(secret_key_t&& other) noexcept = default;

    static secret_key_t Null() { return secret_key_t<NUM_BYTES>(); }
    static secret_key_t FromHex(const std::string& hex) { return secret_key_t<NUM_BYTES>(BigInt<NUM_BYTES>::FromHex(hex)); }

    static secret_key_t Random()
    {
        secret_key_t<NUM_BYTES> key;
        while (true) {
            size_t index = 0;
            while (index < NUM_BYTES) {
                size_t num_bytes = std::min(NUM_BYTES - index, (size_t)32);
                GetStrongRandBytes(Span{key.data() + index, num_bytes});
                index += num_bytes;
            }
            if constexpr (NUM_BYTES == 32) {
                if (key.IsValid()) {
                    break;
                }
            } else {
                break;
            }
        }
        return key;
    }

    static secret_key_t FromHash(const mw::Hash& hash)
    {
        static_assert(NUM_BYTES == 32, "Only 32-byte secret keys can be derived from hashes");

        secret_key_t key(hash);
        if (key.IsValid()) {
            return key;
        }

        uint32_t counter = 0;
        do {
            blake3_hasher hasher;
            blake3_hasher_init(&hasher);

            static constexpr char tag[] = "MWEB hash-to-scalar";
            blake3_hasher_update(&hasher, tag, sizeof(tag) - 1);
            blake3_hasher_update(&hasher, hash.data(), hash.size());

            std::array<uint8_t, 4> counter_bytes{
                static_cast<uint8_t>(counter),
                static_cast<uint8_t>(counter >> 8),
                static_cast<uint8_t>(counter >> 16),
                static_cast<uint8_t>(counter >> 24)
            };
            blake3_hasher_update(&hasher, counter_bytes.data(), counter_bytes.size());
            blake3_hasher_finalize(&hasher, key.data(), key.size());
            counter++;
        } while (!key.IsValid());

        return key;
    }

    //
    // Destructor
    //
    virtual ~secret_key_t() = default;

    //
    // Operators
    //
    secret_key_t<NUM_BYTES>& operator=(const secret_key_t<NUM_BYTES>& other) = default;
    secret_key_t<NUM_BYTES>& operator=(secret_key_t<NUM_BYTES>&& other) noexcept = default;
    bool operator<(const secret_key_t<NUM_BYTES>& rhs) const noexcept { return m_value < rhs.m_value; }
    bool operator==(const secret_key_t<NUM_BYTES>& rhs) const noexcept { return m_value == rhs.m_value; }
    bool operator!=(const secret_key_t<NUM_BYTES>& rhs) const noexcept { return m_value != rhs.m_value; }

    //
    // Getters
    //
    const BigInt<NUM_BYTES>& GetBigInt() const { return m_value; }
    std::string ToHex() const noexcept { return m_value.ToHex(); }
    bool IsNull() const noexcept { return m_value.IsZero(); }
    bool IsValid() const noexcept
    {
        if constexpr (NUM_BYTES == 32) {
            return IsValidBytes(data());
        } else {
            return !IsNull();
        }
    }
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
    IMPL_SERIALIZABLE(secret_key_t<NUM_BYTES>, obj)
    {
        READWRITE(obj.m_value);
    }

private:
    static bool IsValidBytes(const uint8_t* bytes) noexcept
    {
        static constexpr std::array<uint8_t, 32> SECP256K1_ORDER{{
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
            0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
            0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
        }};

        bool nonzero = false;
        for (size_t i = 0; i < 32; i++) {
            if (bytes[i] != 0) {
                nonzero = true;
                break;
            }
        }
        if (!nonzero) {
            return false;
        }

        for (size_t i = 0; i < 32; i++) {
            if (bytes[i] != SECP256K1_ORDER[i]) {
                return bytes[i] < SECP256K1_ORDER[i];
            }
        }

        return false;
    }

    BigInt<NUM_BYTES> m_value;
};

using SecretKey = secret_key_t<32>;
using BlindingFactor = secret_key_t<32>;
using SecretKey64 = secret_key_t<64>;
