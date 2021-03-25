#pragma once

// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <string>

namespace Traits
{
    class IPrintable
    {
    public:
        virtual ~IPrintable() = default;

        virtual std::string Format() const = 0;
    };
}