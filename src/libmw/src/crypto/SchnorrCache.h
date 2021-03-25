#pragma once

#include <mw/models/crypto/SignedMessage.h>
#include <caches/Cache.h>
#include <mutex>

class SchnorrCache
{
public:
    SchnorrCache() : m_cache(3000) {}

    void Add(const SignedMessage& signed_message)
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_cache.Put(signed_message, signed_message);
    }

    bool Contains(const SignedMessage& signed_message) const
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        return m_cache.Cached(signed_message);
    }

private:
    mutable std::mutex m_mutex;
    mutable LRUCache<SignedMessage, SignedMessage> m_cache;
};