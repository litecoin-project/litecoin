#pragma once

#include <libmw/libmw.h>
#include <mw/common/BitSet.h>
#include <mw/models/block/Header.h>
#include <mw/models/tx/Kernel.h>
#include <mw/models/tx/UTXO.h>
#include <mw/traits/Serializable.h>

MW_NAMESPACE

struct State
{
    mw::Hash header_hash;
    std::vector<Kernel> kernels;
    BitSet leafset;
    std::vector<UTXO::CPtr> utxos;
    std::vector<Hash> pruned_parent_hashes;

    static State Deserialize(Deserializer& deserializer)
    {
        Hash header_hash = deserializer.Read<Hash>();
        std::vector<Kernel> kernels = deserializer.ReadVec<Kernel>();

        BitSet leafset = deserializer.Read<BitSet>();

        const uint64_t num_utxos = deserializer.Read<uint64_t>();
        std::vector<UTXO::CPtr> utxos(num_utxos);
        for (uint64_t i = 0; i < num_utxos; i++) {
            utxos[i] = std::make_shared<UTXO>(deserializer.Read<UTXO>());
        }

        std::vector<Hash> pruned_parent_hashes = deserializer.ReadVec<Hash>();

        return State{
            std::move(header_hash),
            std::move(kernels),
            std::move(leafset),
            std::move(utxos),
            std::move(pruned_parent_hashes)
        };
    }

    std::vector<uint8_t> Serialized() const noexcept
    {
        return Serializer()
            .Append(header_hash)
            .AppendVec(kernels)
            .Append(leafset)
            .AppendVec(utxos)
            .AppendVec(pruned_parent_hashes)
            .vec();
    }
};

END_NAMESPACE