#pragma once

#include <serialize.h>
#include <streams.h>
#include <clientversion.h>
#include <mw/models/crypto/Commitment.h>

struct CoinKey
{
    CoinKey() = default;
    explicit CoinKey(const Commitment& commitment_)
        : commitment(commitment_) { }

    char prefix = 'M';
    Commitment commitment;

    std::string ToString() const
    {
        CDataStream stream(SER_DISK, CLIENT_VERSION);
        Serialize(stream);
        return stream.str();
    }

    template<typename Stream>
    void Serialize(Stream& s) const {
        s << prefix;
        s.write((const char*)commitment.data(), commitment.size());
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> prefix;
        s.read((char*)commitment.data(), commitment.size());
    }
};