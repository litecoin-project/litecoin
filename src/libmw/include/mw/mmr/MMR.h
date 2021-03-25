#pragma once

// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <mw/common/Macros.h>
#include <mw/common/Logger.h>
#include <mw/models/crypto/Hash.h>
#include <mw/traits/Serializable.h>
#include <mw/mmr/Backend.h>
#include <mw/mmr/LeafIndex.h>
#include <mw/mmr/Leaf.h>
#include <mw/mmr/Node.h>
#include <libmw/interfaces/db_interface.h>

MMR_NAMESPACE

/// <summary>
/// An interface for interacting with MMRs.
/// </summary>
class IMMR
{
public:
    using Ptr = std::shared_ptr<IMMR>;

    /// <summary>
    /// Adds a new leaf with the given data to the end of the MMR.
    /// </summary>
    /// <param name="data">The serialized leaf data.</param>
    /// <returns>The LeafIndex where the data was added.</returns>
    virtual LeafIndex AddLeaf(std::vector<uint8_t>&& data) = 0;
    LeafIndex Add(const std::vector<uint8_t>& data) { return AddLeaf(std::vector<uint8_t>(data)); }
    LeafIndex Add(const Traits::ISerializable& serializable) { return AddLeaf(serializable.Serialized()); }

    /// <summary>
    /// Retrieves the leaf at the given leaf index.
    /// </summary>
    /// <param name="leafIdx">The leaf index.</param>
    /// <returns>The retrieved Leaf.</returns>
    /// <throws>std::exception if index is beyond the end of the MMR.</throws>
    /// <throws>std::exception if leaf at given index has been pruned.</throws>
    virtual Leaf GetLeaf(const LeafIndex& leafIdx) const = 0;

    /// <summary>
    /// Retrieves the hash at the given MMR index.
    /// </summary>
    /// <param name="idx">The index, which may or may not be a leaf.</param>
    /// <returns>The hash of the leaf or node at the index.</returns>
    /// <throws>std::exception if index is beyond the end of the MMR.</throws>
    /// <throws>std::exception if node at the given index has been pruned.</throws>
    virtual mw::Hash GetHash(const Index& idx) const = 0;

    /// <summary>
    /// Retrieves the index of the next leaf to be added to the MMR.
    /// eg. If the MMR contains 3 leaves (0, 1, 2), this will return LeafIndex 3.
    /// </summary>
    /// <returns>The next leaf index.</returns>
    virtual LeafIndex GetNextLeafIdx() const noexcept = 0;

    /// <summary>
    /// Gets the number of leaves in the MMR, including those that have been pruned.
    /// eg. If the MMR contains leaves 0, 1, and 2, this will return 3.
    /// </summary>
    /// <returns>The number of (pruned and unpruned) leaves in the MMR.</returns>
    uint64_t GetNumLeaves() const noexcept { return GetNextLeafIdx().GetLeafIndex(); }

    /// <summary>
    /// "Rewinds" the MMR to the given number of leaves.
    /// In other words, it shrinks the MMR to the given size.
    /// </summary>
    /// <param name="numLeaves">The total number of (pruned and unpruned) leaves in the MMR.</param>
    virtual void Rewind(const uint64_t numLeaves) = 0;
    void Rewind(const LeafIndex& nextLeaf) { Rewind(nextLeaf.GetLeafIndex()); }
    
    /// <summary>
    /// Unlike a Merkle tree, an MMR generally has no single root so we need a method to compute one.
    /// The process we use is called "bagging the peaks." We first identify the peaks (nodes with no parents).
    /// We then "bag" them by hashing them iteratively from the right, using the total size of the MMR as prefix. 
    /// </summary>
    /// <returns>The root hash of the MMR.</returns>
    mw::Hash Root() const;

    /// <summary>
    /// Adds the given leaves to the MMR.
    /// This also updates the database and MMR files when the MMR is not a cache.
    /// Typically, this is called from a derived MMRCache when its changes are being flushed/committed.
    /// </summary>
    /// <param name="file_index">The index of the MMR files. This should be incremented with each write.</param>
    /// <param name="firstLeafIdx">The LeafIndex of the first leaf being added.</param>
    /// <param name="leaves">The leaves being added to the MMR.</param>
    /// <param name="pBatch">A wrapper around a DB Batch. Required when called for an MMR (ie, non-cache).</param>
    virtual void BatchWrite(
        const uint32_t file_index,
        const LeafIndex& firstLeafIdx,
        const std::vector<Leaf>& leaves,
        const std::unique_ptr<libmw::IDBBatch>& pBatch
    ) = 0;
};

class MMR : public IMMR
{
public:
    using Ptr = std::shared_ptr<MMR>;

    MMR(const IBackend::Ptr& pBackend) : m_pBackend(pBackend) { }

    LeafIndex AddLeaf(std::vector<uint8_t>&& data) final;

    Leaf GetLeaf(const LeafIndex& leafIdx) const final { return m_pBackend->GetLeaf(leafIdx); }
    mw::Hash GetHash(const Index& idx) const final { return m_pBackend->GetHash(idx); }
    LeafIndex GetNextLeafIdx() const noexcept final { return m_pBackend->GetNextLeaf(); }

    uint64_t GetNumLeaves() const noexcept;
    uint64_t GetNumNodes() const noexcept;
    void Rewind(const uint64_t numLeaves) final;

    void BatchWrite(
        const uint32_t file_index,
        const LeafIndex& firstLeafIdx,
        const std::vector<Leaf>& leaves,
        const std::unique_ptr<libmw::IDBBatch>& pBatch
    ) final;

private:
    IBackend::Ptr m_pBackend;
};

class MMRCache : public IMMR
{
public:
    using Ptr = std::shared_ptr<MMRCache>;

    MMRCache(const IMMR::Ptr& pBacked)
        : m_pBase(pBacked), m_firstLeaf(pBacked->GetNextLeafIdx()){ }

    LeafIndex AddLeaf(std::vector<uint8_t>&& data) final;

    Leaf GetLeaf(const LeafIndex& leafIdx) const final;
    LeafIndex GetNextLeafIdx() const noexcept final;
    mw::Hash GetHash(const Index& idx) const final;

    void Rewind(const uint64_t numLeaves) final;

    void BatchWrite(
        const uint32_t file_index,
        const LeafIndex& firstLeafIdx,
        const std::vector<Leaf>& leaves,
        const std::unique_ptr<libmw::IDBBatch>& pBatch
    ) final;

    void Flush(const uint32_t index, const std::unique_ptr<libmw::IDBBatch>& pBatch);

private:
    IMMR::Ptr m_pBase;
    LeafIndex m_firstLeaf;
    std::vector<Leaf> m_leaves;
    std::vector<mw::Hash> m_nodes;
};

END_NAMESPACE