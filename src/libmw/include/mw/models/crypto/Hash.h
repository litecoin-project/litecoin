#pragma once

// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <mw/common/Macros.h>
#include <mw/models/crypto/BigInteger.h>
#include <boost/container_hash/hash.hpp>

MW_NAMESPACE

using Hash = BigInt<32>;

END_NAMESPACE

#define ZERO_HASH mw::Hash::ValueOf(0)

namespace std
{
    template<>
    struct hash<mw::Hash>
    {
        size_t operator()(const mw::Hash& hash) const
        {
            return boost::hash_value(hash.vec());
        }
    };
}