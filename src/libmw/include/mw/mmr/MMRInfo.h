#pragma once

#include <mw/common/Traits.h>
#include <mw/models/block/Header.h>
#include <optional>

/// <summary>
/// Represents the state of the MMR files with the matching index.
/// </summary>
struct MMRInfo : public Traits::ISerializable
{
    MMRInfo()
        : version(0), index(0), pruned(mw::Hash()), compact_index(0), compacted(std::nullopt) { }
    MMRInfo(uint8_t version, uint32_t index_in, mw::Hash pruned_in, uint32_t compact_index_in, std::optional<mw::Header> compacted_in)
        : version(version), index(index_in), pruned(std::move(pruned_in)), compact_index(compact_index_in), compacted(std::move(compacted_in)) { }

    // Version byte that allows for future modifications to the MMRInfo schema.
    uint8_t version;

    // File number of the PMMR files.
    uint32_t index;

    // Hash of latest header this PMMR represents.
    mw::Hash pruned;

    // File number of the PruneList bitset.
    uint32_t compact_index;

    // Header this PMMR was compacted for (version 2).
    // You cannot rewind beyond this point.
    std::optional<mw::Header> compacted;

    // Version 2 records resumable leaf cleanup.
    bool cleanup_pending{false};
    
    IMPL_SERIALIZABLE(MMRInfo, obj)
    {
        READWRITE(obj.version, obj.index, obj.pruned, obj.compact_index);
        if (obj.version >= 2) {
            READWRITE(obj.compacted, obj.cleanup_pending);
        } else {
            // Versions 0 and 1 reserved an optional hash but never populated it.
            std::optional<mw::Hash> legacy_compacted;
            READWRITE(legacy_compacted);
            SER_READ(obj, obj.compacted.reset(); obj.cleanup_pending = false);
            if (legacy_compacted || obj.compacted) {
                throw std::ios_base::failure("Unsupported legacy MWEB compaction metadata");
            }
        }
    }
};
