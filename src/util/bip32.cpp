// Copyright (c) 2019-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <tinyformat.h>
#include <util/bip32.h>
#include <util/strencodings.h>

#include <cstdint>
#include <cstdio>
#include <sstream>

bool ParseHDKeypath(const std::string& keypath_str, HDKeyPath& hdkeypath)
{
    hdkeypath.clear();

    std::stringstream ss(keypath_str);
    std::string item;
    bool first = true;
    bool has_mweb = false;
    while (std::getline(ss, item, '/')) {
        // MWEB index should be the last item parsed
        if (hdkeypath.mweb_index.has_value()) {
            return false;
        }
        if (item.compare("m") == 0) {
            if (first) {
                first = false;
                continue;
            }
            return false;
        }
        if (item.compare("x") == 0) {
            if (has_mweb || !first) {
                return false;
            }
            has_mweb = true;
            first = false;
            continue;
        }
        // Finds whether it is hardened
        uint32_t path = 0;
        size_t pos = item.find("'");
        if (pos != std::string::npos) {
            // There's no such thing as a hardened mweb_index
            if (has_mweb) {
                return false;
            }
            // The hardened tick can only be in the last index of the string
            if (pos != item.size() - 1) {
                return false;
            }
            path |= 0x80000000;
            item = item.substr(0, item.size() - 1); // Drop the last character which is the hardened tick
        }

        // Ensure this is only numbers
        if (item.find_first_not_of( "0123456789" ) != std::string::npos) {
            return false;
        }
        uint32_t number;
        if (!ParseUInt32(item, &number)) {
            return false;
        }
        path |= number;

        if (has_mweb) {
            hdkeypath.mweb_index = path;
        } else {
            hdkeypath.path.push_back(path);
        }
        first = false;
    }
    return !has_mweb || hdkeypath.mweb_index.has_value();
}

std::string FormatHDKeypath(const HDKeyPath& hdkeypath)
{
    std::string ret;
    for (auto i : hdkeypath.path) {
        ret += strprintf("/%i", (i << 1) >> 1);
        if (i >> 31) ret += '\'';
    }
    return ret;
}

std::string WriteHDKeypath(const HDKeyPath& hdkeypath)
{
    if (hdkeypath.mweb_index.has_value() && hdkeypath.path.empty()) {
        return strprintf("x/%i", *hdkeypath.mweb_index);
    }

    return "m" + FormatHDKeypath(hdkeypath);
}
