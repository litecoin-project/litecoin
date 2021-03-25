#pragma once
#pragma warning(disable: 4505) // Unreferenced local function has been removed

// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <cstdint>
#include <mw/exceptions/DeserializationException.h>

// TODO: Not needed if we decide not to require peg-in outputs to mature.
enum EOutputFeatures : uint8_t
{
    // No Flags
    DEFAULT_OUTPUT = 0,

    // Output is a pegged-in output, must not be spent until maturity
    PEGGED_IN = 1
};

class Features
{
public:
    Features() noexcept : m_features(0) {}
    Features(const uint8_t features) noexcept : m_features(features) {}
    Features(const EOutputFeatures features) noexcept : m_features((uint8_t)features) {}

    bool operator==(const uint8_t features) const noexcept { return m_features == features; }
    bool operator==(const EOutputFeatures& features) const noexcept { return m_features == features; }

    bool IsSet(const uint8_t feature) const noexcept { return (m_features & feature) == feature; }
    uint8_t Get() const noexcept { return m_features; }

private:
    uint8_t m_features;
};

namespace OutputFeatures
{
    static std::string ToString(const EOutputFeatures& features) noexcept
    {
        switch (features)
        {
            case DEFAULT_OUTPUT:
                return "Plain";
            case PEGGED_IN:
                return "PeggedIn";
        }

        return "";
    }

    static EOutputFeatures FromString(const std::string& string)
    {
        if (string == "Plain")
        {
            return EOutputFeatures::DEFAULT_OUTPUT;
        }
        else if (string == "PeggedIn")
        {
            return EOutputFeatures::PEGGED_IN;
        }

        ThrowDeserialization_F("Failed to deserialize output feature: {}", string);
    }
}