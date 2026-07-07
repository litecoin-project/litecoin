// Copyright (c) 2019-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_KEYORIGIN_H
#define BITCOIN_SCRIPT_KEYORIGIN_H

#include <util/bip32.h>
#include <serialize.h>
#include <optional>
#include <vector>

struct KeyOriginInfo
{
    unsigned char fingerprint[4]; //!< First 32 bits of the Hash160 of the public key at the root of the path
    HDKeyPath hdkeypath;

    SERIALIZE_METHODS(KeyOriginInfo, obj)
    {
        READWRITE(obj.fingerprint, obj.hdkeypath);
    }

    friend bool operator==(const KeyOriginInfo& a, const KeyOriginInfo& b)
    {
        return std::equal(std::begin(a.fingerprint), std::end(a.fingerprint), std::begin(b.fingerprint)) && a.hdkeypath == b.hdkeypath;
    }

    friend bool operator<(const KeyOriginInfo& a, const KeyOriginInfo& b)
    {
        // Compare the fingerprints lexicographically
        int fpr_cmp = memcmp(a.fingerprint, b.fingerprint, 4);
        if (fpr_cmp < 0) {
            return true;
        } else if (fpr_cmp > 0) {
            return false;
        }

        // Compare the MWEB indices
        return a.hdkeypath < b.hdkeypath;
    }

    void clear()
    {
        memset(fingerprint, 0, 4);
        hdkeypath.clear();
    }
};

#endif // BITCOIN_SCRIPT_KEYORIGIN_H
