#pragma once

// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <mw/models/crypto/BigInteger.h>
#include <mw/models/wallet/KeyChainPath.h>

class ProofMessage
{
public:
    ProofMessage() = default;
    ProofMessage(BigInt<20>&& bytes) : m_bytes(std::move(bytes)) { }

    static ProofMessage FromKeyChain(const KeyChainPath& keyChainPath)
    {
        BigInt<20> paddedPath = BigInt<20>::ValueOf(0);
        paddedPath[2] = 1;
        paddedPath[3] = (uint8_t)keyChainPath.GetKeyIndices().size();

        Serializer serializer;
        for (const uint32_t keyIndex : keyChainPath.GetKeyIndices()) {
            serializer.Append(keyIndex);
        }

        for (size_t i = 0; i < serializer.size(); i++) {
            paddedPath[i + 4] = serializer.vec()[i];
        }

        return ProofMessage(std::move(paddedPath));
    }

    KeyChainPath ToKeyChainPath() const
    {
        Deserializer deserializer(m_bytes.vec());

        deserializer.Read<uint8_t>(); // RESERVED: Always 0
        deserializer.Read<uint8_t>(); // Wallet Type
        deserializer.Read<uint8_t>(); // Switch Commits - Always true for now.
        size_t length = deserializer.Read<uint8_t>();

        if (length == 0) {
            length = 3;
        }

        std::vector<uint32_t> keyIndices(length);
        for (size_t i = 0; i < length; i++)
        {
            keyIndices[i] = deserializer.Read<uint32_t>();
        }

        return KeyChainPath(std::move(keyIndices));
    }

    const BigInt<20>& GetBytes() const { return m_bytes; }
    const uint8_t* data() const { return m_bytes.data(); }

private:
    BigInt<20> m_bytes;
};