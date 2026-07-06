#pragma once

// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <mw/common/Traits.h>

#include <algorithm>
#include <optional>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

class Deserializer
{
public:
    Deserializer(std::vector<uint8_t> bytes)
        : m_bytes(std::move(bytes)), m_reader(SER_NETWORK, PROTOCOL_VERSION, Span{m_bytes}) {}

    template <class T, typename SFINAE = std::enable_if_t<std::is_integral<T>::value || std::is_base_of<Traits::ISerializable, T>::value>>
    T Read()
    {
        T value;
        m_reader >> value;
        return value;
    }

    std::vector<uint8_t> ReadVector(const uint64_t numBytes)
    {
        std::vector<uint8_t> vec(numBytes);
        m_reader.read(AsWritableBytes(Span{vec.data(), numBytes}));
        return vec;
    }

private:
    std::vector<uint8_t> m_bytes;
    SpanReader m_reader;
};
