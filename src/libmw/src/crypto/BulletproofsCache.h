#pragma once

#include <caches/Cache.h>
#include <mw/models/crypto/ProofData.h>
#include <mutex>

class BulletProofsCache
{
public:
    BulletProofsCache() : m_bulletproofsCache(3000) { }

    void Add(const ProofData& proof)
    {
        std::unique_lock<std::mutex> lock(m_mutex);

        m_bulletproofsCache.Put(proof.commitment, proof);
    }

    bool Contains(const ProofData& proof) const
    {
        std::unique_lock<std::mutex> lock(m_mutex);

        if (m_bulletproofsCache.Cached(proof.commitment))
        {
            return proof == m_bulletproofsCache.Get(proof.commitment);
        }

        return false;
    }

private:
    mutable std::mutex m_mutex;
    mutable LRUCache<Commitment, ProofData> m_bulletproofsCache;
};