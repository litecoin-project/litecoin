#pragma once

#include <clientversion.h>
#include <streams.h>
#include <serialize.h>
#include <mw/models/tx/UTXO.h>

struct CoinEntry
{
    std::vector<UTXO::CPtr> utxos;

    std::vector<uint8_t> Serialized() const
    {
        CDataStream stream(SER_DISK, CLIENT_VERSION);
        Serialize(stream);
        return std::vector<uint8_t>{ stream.begin(), stream.end() };
    }

    static CoinEntry Deserialize(const std::vector<uint8_t>& bytes)
    {
        CDataStream stream(bytes, SER_DISK, CLIENT_VERSION);

        CoinEntry coinEntry;
        coinEntry.Unserialize(stream);
        return coinEntry;
    }

    template<typename Stream>
    void Serialize(Stream& s) const {
        s << VARINT(utxos.size());
        for (const UTXO::CPtr& pUTXO : utxos) {
            s << pUTXO->Serialized();
        }
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        size_t numUTXOs;
        s >> VARINT(numUTXOs);

        utxos.reserve(numUTXOs);
        for (size_t i = 0; i < numUTXOs; i++) {
            std::vector<uint8_t> serialized;
            s >> serialized;
            Deserializer deserializer{std::move(serialized)};
            UTXO utxo = UTXO::Deserialize(deserializer);
            utxos.push_back(std::make_shared<UTXO>(std::move(utxo)));
        }
    }
};