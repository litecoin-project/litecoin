#pragma once

// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <mw/util/EndianUtil.h>
#include <mw/exceptions/DeserializationException.h>
#include <mw/traits/Serializable.h>

#include <boost/optional.hpp>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <algorithm>

class Deserializer
{
public:
    Deserializer(const std::vector<uint8_t>& bytes) : m_index(0), m_bytes(bytes) { }
    Deserializer(std::vector<uint8_t>&& bytes) : m_index(0), m_bytes(std::move(bytes)) { }

    template <class T, typename SFINAE = std::enable_if_t<std::is_fundamental_v<T>>>
    T Read()
    {
        T value;
        ReadBigEndian<T>(value);
        return value;
    }

    template <class T, typename SFINAE = std::enable_if_t<std::is_base_of_v<Traits::ISerializable, T>>>
    decltype(auto) Read()
    {
        return T::Deserialize(*this);
    }

    template <class T, typename SFINAE = std::enable_if_t<std::is_base_of_v<Traits::ISerializable, T>>>
    boost::optional<T> ReadOpt()
    {
        if (Read<bool>()) {
            return { T::Deserialize(*this) };
        }

        return boost::none;
    }

    template <class T, typename SFINAE = std::enable_if_t<std::is_fundamental_v<T>>>
    T ReadLE()
    {
        T value;
        ReadLittleEndian<T>(value);
        return value;
    }

    template <class T, typename SFINAE = typename std::enable_if_t<std::is_base_of_v<Traits::ISerializable, T>>>
    std::vector<T> ReadVec()
    {
        const uint32_t num_entries = Read<uint32_t>();
        std::vector<T> vec(num_entries);
        for (uint32_t i = 0; i < num_entries; i++) {
            vec[i] = T::Deserialize(*this);
        }

        return vec;
    }

    std::vector<uint8_t> ReadVector(const uint64_t numBytes)
    {
        if (m_index + numBytes > m_bytes.size())
        {
            ThrowDeserialization("Attempted to read past end of buffer.");
        }

        const size_t index = m_index;
        m_index += numBytes;

        return std::vector<uint8_t>(m_bytes.cbegin() + index, m_bytes.cbegin() + index + numBytes);
    }

    template<size_t T>
    std::array<uint8_t, T> ReadArray()
    {
        if (m_index + T > m_bytes.size())
        {
            ThrowDeserialization("Attempted to read past end of buffer.");
        }

        const size_t index = m_index;
        m_index += T;

        std::array<uint8_t, T> arr;
        std::copy(m_bytes.begin() + index, m_bytes.begin() + index + T, arr.begin());
        return arr;
    }

    size_t GetRemainingSize() const
    {
        return m_bytes.size() - m_index;
    }

private:
    template<class T>
    void ReadBigEndian(T& t)
    {
        if (m_index + sizeof(T) > m_bytes.size())
        {
            ThrowDeserialization("Attempted to read past end of buffer.");
        }

        if (EndianUtil::IsBigEndian())
        {
            memcpy(&t, &m_bytes[m_index], sizeof(T));
        }
        else
        {
            std::vector<uint8_t> temp;
            temp.resize(sizeof(T));
            std::reverse_copy(m_bytes.cbegin() + m_index, m_bytes.cbegin() + m_index + sizeof(T), temp.begin());
            memcpy(&t, temp.data(), sizeof(T));
        }

        m_index += sizeof(T);
    }

    template<class T>
    void ReadLittleEndian(T& t)
    {
        if (m_index + sizeof(T) > m_bytes.size())
        {
            ThrowDeserialization("Attempted to read past end of Deserializer.");
        }

        if (EndianUtil::IsBigEndian())
        {
            std::vector<uint8_t> temp((size_t)sizeof(T));
            std::reverse_copy(m_bytes.cbegin() + m_index, m_bytes.cbegin() + m_index + sizeof(T), temp.begin());
            memcpy(&t, temp.data(), sizeof(T));
        }
        else
        {
            memcpy(&t, &m_bytes[m_index], sizeof(T));
        }

        m_index += sizeof(T);
    }

    size_t m_index;
    std::vector<uint8_t> m_bytes;
};
