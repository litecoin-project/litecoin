// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <crypto/common.h>
#include <crypto/scrypt.h>

uint256 CBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

uint256 CBlockHeader::GetPoWHash() const
{
    uint256 thash;
    scrypt_1024_1_1_256(BEGIN(nVersion), BEGIN(thash));
    return thash;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}

CTransactionRef CBlock::GetHogEx() const noexcept
{
    if (vtx.size() >= 2 && vtx.back()->IsHogEx()) {
        assert(!vtx.back()->vout.empty());
        return vtx.back();
    }

    return nullptr;
}

uint256 CBlock::GetMWEBHash() const noexcept
{
    auto pHogEx = GetHogEx();
    if (pHogEx != nullptr) {
        int version;
        std::vector<unsigned char> program;
        if (pHogEx->vout.front().scriptPubKey.IsWitnessProgram(version, program)) {
            if (program.size() == WITNESS_MWEB_HEADERHASH_SIZE && version == MWEB_WITNESS_VERSION) {
                return uint256(program);
            }
        }
    }

    return uint256();
}

// The amount of the first output in the HogEx transaction.
CAmount CBlock::GetMWEBAmount() const noexcept
{
    auto pHogEx = GetHogEx();
    return pHogEx ? pHogEx->vout.front().nValue : 0;
}