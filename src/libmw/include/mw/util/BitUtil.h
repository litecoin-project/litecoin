#pragma once

// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <cstdint>

class BitUtil
{
public:
    static uint64_t FillOnesToRight(const uint64_t input) noexcept
    {
        uint64_t x = input;
        x = x | (x >> 1);
        x = x | (x >> 2);
        x = x | (x >> 4);
        x = x | (x >> 8);
        x = x | (x >> 16);
        x = x | (x >> 32);
        return x;
    }

    //
    // Counts the number of bits set to 1.
    //
    static uint8_t CountBitsSet(const uint64_t input) noexcept
    {
        uint64_t n = input;
        uint8_t count = 0;
        while (n)
        {
            count += (uint8_t)(n & 1);
            n >>= 1;
        }

        return count;
    }

    static uint8_t CountRightmostZeros(const uint64_t input) noexcept
    {
        uint8_t count = 0;

        uint64_t n = input;
        while ((n & 1) == 0) {
            ++count;
            n >>= 1;
        }

        return count;
    }

    //
    // Creates uint16_t from given bytes. Bytes should be passed in order from MSB to LSB.
    //
    static uint16_t ConvertToU16(const uint8_t byte1, const uint8_t byte2) noexcept
    {
        return (((uint16_t)byte1) << 8) | ((uint16_t)byte2);
    }

    //
    // Creates uint32_t from given bytes. Bytes should be passed in order from MSB to LSB.
    //
    static uint32_t ConvertToU32(const uint8_t byte1, const uint8_t byte2, const uint8_t byte3, const uint8_t byte4) noexcept
    {
        return ((((uint32_t)byte1) << 24) | (((uint32_t)byte2) << 16) | (((uint32_t)byte3) << 8) | ((uint32_t)byte4));
    }

    //
    // Creates uint64_t from given bytes. Bytes should be passed in order from MSB to LSB.
    //
    static uint64_t ConvertToU64(const uint8_t byte1, const uint8_t byte2, const uint8_t byte3, const uint8_t byte4,
        const uint8_t byte5, const uint8_t byte6, const uint8_t byte7, const uint8_t byte8) noexcept
    {
        return ((((uint64_t)byte1) << 56) | (((uint64_t)byte2) << 48) | (((uint64_t)byte3) << 40) | ((uint64_t)byte4) << 32
            | ((uint64_t)byte5) << 24 | ((uint64_t)byte6) << 16 | ((uint64_t)byte7) << 8 | ((uint64_t)byte8));
    }
};