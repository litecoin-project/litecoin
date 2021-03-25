#pragma once

// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <cstring>
#include <cstdint>

//
// A header-only utility for determining and changing endianness of data.
//
class EndianUtil
{
public:
    static bool IsBigEndian() noexcept
    {
        union
        {
            uint32_t i;
            char c[4];
        } bint = { 0x01020304 };

        return bint.c[0] == 1;
    }

    // In Visual Studio, _byteswap_ushort could be used.
    static uint16_t changeEndianness16(const uint16_t val) noexcept
    {
        return (val << 8) |          // left-shift always fills with zeros
            ((val >> 8) & 0x00ff); // right-shift sign-extends, so force to zero
    }

    // In Visual Studio, _byteswap_ulong could be used.
    static uint32_t changeEndianness32(const uint32_t val) noexcept
    {
        return (val << 24) |
            ((val << 8) & 0x00ff0000) |
            ((val >> 8) & 0x0000ff00) |
            ((val >> 24) & 0x000000ff);
    }

    static uint64_t changeEndianness64(const uint64_t val) noexcept
    {
        uint64_t x = val;
        x = (x & 0x00000000FFFFFFFF) << 32 | (x & 0xFFFFFFFF00000000) >> 32;
        x = (x & 0x0000FFFF0000FFFF) << 16 | (x & 0xFFFF0000FFFF0000) >> 16;
        x = (x & 0x00FF00FF00FF00FF) << 8 | (x & 0xFF00FF00FF00FF00) >> 8;
        return x;
    }

    static uint16_t GetBigEndian16(const uint16_t val) noexcept
    {
        if (IsBigEndian())
        {
            return val;
        }

        return changeEndianness16(val);
    }

    static uint32_t GetBigEndian32(const uint32_t val) noexcept
    {
        if (IsBigEndian())
        {
            return val;
        }

        return changeEndianness32(val);
    }

    static uint64_t GetBigEndian64(const uint64_t val) noexcept
    {
        if (IsBigEndian())
        {
            return val;
        }

        return changeEndianness64(val);
    }

    static uint32_t GetLittleEndian32(const uint32_t val) noexcept
    {
        if (!IsBigEndian())
        {
            return val;
        }

        return changeEndianness32(val);
    }

    static uint64_t GetLittleEndian64(const uint64_t val) noexcept
    {
        if (!IsBigEndian())
        {
            return val;
        }

        return changeEndianness64(val);
    }

    static uint32_t ReadBE32(const uint8_t* ptr)
    {
        uint32_t x;
        memcpy((char*)&x, ptr, 4);

        return GetBigEndian32(x);
    }

    static uint64_t ReadBE64(const uint8_t* ptr)
    {
        uint64_t x;
        memcpy((char*)&x, ptr, 8);

        return GetBigEndian64(x);
    }

    static void WriteBE32(uint8_t* ptr, uint32_t x)
    {
        uint32_t v = GetBigEndian32(x);
        memcpy(ptr, (char*)&v, 4);
    }

    static void WriteBE64(uint8_t* ptr, uint64_t x)
    {
        uint64_t v = GetBigEndian64(x);
        memcpy(ptr, (char*)&v, 8);
    }

    static uint32_t ReadLE32(const uint8_t* ptr)
    {
        uint32_t x;
        memcpy((char*)&x, ptr, 4);

        return GetLittleEndian32(x);
    }

    static void WriteLE32(uint8_t* ptr, uint32_t x)
    {
        uint32_t v = GetLittleEndian32(x);
        memcpy(ptr, (char*)&v, 4);
    }

    static void WriteLE64(uint8_t* ptr, uint64_t x)
    {
        uint64_t v = GetLittleEndian64(x);
        memcpy(ptr, (char*)&v, 8);
    }
};
