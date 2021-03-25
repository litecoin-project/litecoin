#pragma once

#include <hash.h>
#include <crypto/sha512.h>
#include <mw/models/crypto/Hash.h>
#include <mw/traits/Serializable.h>

enum class EHashTag : char
{
    ADDRESS = 'A',
    SEND_KEY = 'S',
    DERIVE = 'D',
    OUT_KEY = 'O',
    NONCE = 'N'
};

// FUTURE: Incrementally update hash on each Append using CSHA256.write()
class Hasher
{
public:
    Hasher() = default;
    Hasher(const EHashTag tag)
    {
        m_serializer.Append<char>(static_cast<char>(tag));
    }

    mw::Hash hash() const { return mw::Hash(SerializeHash(m_serializer.vec()).begin()); }

    template <class T>
    Hasher& Append(const T& t)
    {
        m_serializer.Append(t);
        return *this;
    }

private:
    Serializer m_serializer;
};

static mw::Hash Hashed(const std::vector<uint8_t>& serialized)
{
    return mw::Hash(SerializeHash(serialized).begin());
}

static mw::Hash Hashed(const Traits::ISerializable& serializable)
{
    Serializer serializer;
    serializable.Serialize(serializer);
    return mw::Hash(SerializeHash(serializer.vec()).begin());
}

static mw::Hash Hashed(const EHashTag tag, const Traits::ISerializable& serializable)
{
    return Hasher(tag).Append(serializable).hash();
}

static const mw::Hash& InputMessage()
{
    static const mw::Hash mweb_hash = Hashed({ 'M', 'W', 'E', 'B' });
    return mweb_hash;
}

static BigInt<64> Hash512(const Traits::ISerializable& serializable)
{
    BigInt<64> ret;

    std::vector<uint8_t> serialized = serializable.Serialized();
    CSHA512()
        .Write(serialized.data(), serialized.size())
        .Finalize(ret.data());
    return ret;
}