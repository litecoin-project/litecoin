#pragma once

// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <mw/util/EndianUtil.h>

#include <cassert>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <ios>
#include <iomanip>

class HexUtil
{
public:
    static bool IsValidHex(const std::string& data)
    {
        if (data.compare(0, 2, "0x") == 0 && data.size() > 2)
        {
            return data.find_first_not_of("0123456789abcdefABCDEF", 2) == std::string::npos;
        }
        else
        {
            return data.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos;
        }
    }

    static std::vector<uint8_t> FromHex(const std::string& hex)
    {
        assert(IsValidHex(hex));

        std::vector<uint8_t> data((hex.size() + 1) / 2);
        for (size_t i = 0; i < hex.length(); i += 2)
        {
            data[i / 2] = (FromHexChar(hex[i]) * 16 + FromHexChar(hex[i + 1]));
        }

        return data;
    }

    static std::string ToHex(const std::vector<uint8_t>& data)
    {
        std::ostringstream stream;
        for (const uint8_t byte : data)
        {
            stream << std::hex << std::setfill('0') << std::setw(2) << std::nouppercase << (int)byte;
        }

        return stream.str();
    }

    static std::string ToHex(const std::vector<uint8_t>& data, const size_t numBytes)
    {
        const std::vector<uint8_t> firstNBytes(data.cbegin(), data.cbegin() + numBytes);

        return ToHex(firstNBytes);
    }

    static std::string ToHex(const uint16_t value) noexcept
    {
        const uint16_t bigEndian = EndianUtil::GetBigEndian16(value);

        std::vector<uint8_t> bytes(2);
        memcpy(&bytes, (uint8_t*)&bigEndian, 2);

        std::string hex = ToHex(bytes);
        const size_t firstNonZero = hex.find_first_not_of('0');
        hex.erase(0, (std::min)(firstNonZero, hex.size() - 1));

        return hex;
    }

private:
    static uint8_t FromHexChar(const char value)
    {
        if (value <= '9' && value >= 0)
        {
            return (uint8_t)(value - '0');
        }

        if (value >= 'a')
        {
            return (uint8_t)(10 + value - 'a');
        }

        return (uint8_t)(10 + value - 'A');
    }
};