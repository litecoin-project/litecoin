// Copyright (c) 2019-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_BIP32_H
#define BITCOIN_UTIL_BIP32_H

#include <serialize.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct HDKeyPath
{
    std::vector<uint32_t> path;
    std::optional<uint32_t> mweb_index{std::nullopt};

    SERIALIZE_METHODS(HDKeyPath, obj)
    {
        READWRITE(obj.path, obj.mweb_index);
    }

    friend bool operator==(const HDKeyPath& a, const HDKeyPath& b)
    {
        return a.path == b.path && a.mweb_index == b.mweb_index;
    }

    friend bool operator<(const HDKeyPath& a, const HDKeyPath& b)
    {
        // Compare the sizes of the paths, shorter is "less than"
        if (a.path.size() < b.path.size()) {
            return true;
        } else if (a.path.size() > b.path.size()) {
            return false;
        }
        // Paths same length, compare them lexicographically
        if (a.path < b.path) {
            return true;
        } else if (a.path > b.path) {
            return false;
        }

        // Compare the MWEB indices
        return a.mweb_index < b.mweb_index;
    }

    void clear()
    {
        path.clear();
        mweb_index.reset();
    }
};

/** Parse an HD keypaths like "m/7/0'/2000". */
[[nodiscard]] bool ParseHDKeypath(const std::string& keypath_str, HDKeyPath& kehdkeypathypath);

/**
 * Write a wallet/RPC keypath string. This includes wallet metadata extensions
 * such as a MWEB-only subaddress index ("x/42"). Use this for displaying or
 * storing CKeyMetadata origins, not for constructing descriptor key paths.
 */
std::string WriteHDKeypath(const HDKeyPath& hdkeypath);

/**
 * Format only the BIP32 derivation suffix, beginning with '/' when non-empty.
 * This intentionally excludes wallet-only metadata such as mweb_index. Use this
 * when serializing descriptor key origins or xpub/xprv derivation suffixes.
 */
std::string FormatHDKeypath(const HDKeyPath& hdkeypath);

#endif // BITCOIN_UTIL_BIP32_H
