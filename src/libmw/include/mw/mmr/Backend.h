#pragma once

// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <mw/common/Macros.h>
#include <mw/models/crypto/Hash.h>
#include <mw/mmr/Index.h>
#include <mw/mmr/LeafIndex.h>
#include <mw/mmr/Leaf.h>
#include <libmw/interfaces/db_interface.h>
#include <boost/dynamic_bitset.hpp>
#include <memory>

MMR_NAMESPACE

class IBackend
{
public:
    using Ptr = std::shared_ptr<IBackend>;
    using CPtr = std::shared_ptr<const IBackend>;

    virtual ~IBackend() = default;

    virtual void AddLeaf(const Leaf& leaf) = 0;
    virtual void AddHash(const mw::Hash& hash) = 0;
    virtual void Rewind(const LeafIndex& nextLeafIndex) = 0;

    /// <summary>
    /// Takes in a bitset of all positions we want to keep.
    /// All other positions in the leafset will be removed,
    /// leaving just enough parents to rebuild & verify the MMR root.
    /// The resulting MMR will be immediately flushed to disk. No need to call Commit().
    /// </summary>
    /// <param name="file_index">The file number to save the compacted MMR hash file.</param>
    /// <param name="hashes_to_remove">The positions to remove.</param>
    virtual void Compact(const uint32_t file_index, const boost::dynamic_bitset<uint64_t>& hashes_to_remove) = 0;

    virtual uint64_t GetNumLeaves() const noexcept = 0;
    virtual mw::Hash GetHash(const Index& idx) const = 0;
    virtual Leaf GetLeaf(const LeafIndex& idx) const = 0;

    virtual LeafIndex GetNextLeaf() const noexcept { return LeafIndex::At(GetNumLeaves()); }

    virtual void Commit(const uint32_t file_index, const std::unique_ptr<libmw::IDBBatch>& pBatch) = 0;
};

END_NAMESPACE