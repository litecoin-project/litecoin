#pragma once

#include <mw/models/crypto/Hash.h>
#include <boost/optional.hpp>

/// <summary>
/// Represents the state of the MMR files with the matching index.
/// </summary>
struct MMRInfo : public Traits::ISerializable
{
    MMRInfo()
        : version(0), index(0), pruned(mw::Hash()), compact_index(0), compacted(boost::none) { }
    MMRInfo(uint8_t version, uint32_t index_in, mw::Hash pruned_in, uint32_t compact_index_in, boost::optional<mw::Hash> compacted_in)
        : version(version), index(index_in), pruned(std::move(pruned_in)), compact_index(compact_index_in), compacted(std::move(compacted_in)) { }

    // Version byte that allows for future modifications to the MMRInfo schema.
    uint8_t version;

    // File number of the MMR files.
    uint32_t index;

    // Hash of latest header this MMR represents.
    mw::Hash pruned;

    // File number of the PruneList bitset.
    uint32_t compact_index;

    // Hash of the header this MMR was compacted for.
    // You cannot rewind beyond this point.
    boost::optional<mw::Hash> compacted;

    Serializer& Serialize(Serializer& serializer) const noexcept final
    {
        return serializer
            .Append<uint8_t>(version)
            .Append<uint32_t>(index)
            .Append(pruned)
            .Append<uint32_t>(compact_index)
            .Append(compacted.value_or(mw::Hash()));
    }

    static MMRInfo Deserialize(Deserializer& deserializer)
    {
        uint8_t version = deserializer.Read<uint8_t>();
        uint32_t index = deserializer.Read<uint32_t>();
        mw::Hash pruned = deserializer.Read<mw::Hash>();
        uint32_t compact_index = deserializer.Read<uint32_t>();
        mw::Hash compacted = deserializer.Read<mw::Hash>();

        return MMRInfo{
            version,
            index,
            pruned,
            compact_index,
            compacted == mw::Hash() ? boost::none : boost::make_optional<mw::Hash>(std::move(compacted))
        };
    }
};