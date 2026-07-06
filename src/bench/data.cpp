// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/data.h>

namespace benchmark {
namespace data {

#include <bench/data/block878439.raw.h>
const std::vector<uint8_t> block878439{std::begin(block878439_raw), std::end(block878439_raw)};

} // namespace data
} // namespace benchmark
