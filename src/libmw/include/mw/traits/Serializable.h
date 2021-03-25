#pragma once

// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <cstdint>
#include <vector>

// Forward Declarations
class Serializer;

namespace Traits
{
    class ISerializable
    {
    public:
        virtual ~ISerializable() = default;

        //
        // Appends serialized bytes to Serializer
        //
        virtual Serializer& Serialize(Serializer& serializer) const noexcept = 0;

        //
        // Serializes object into a byte vector.
        //
        std::vector<uint8_t> Serialized() const noexcept;
    };
}