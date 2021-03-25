#include <mw/mmr/MMRFactory.h>
#include <mw/mmr/MMRUtil.h>
#include <mw/mmr/Node.h>
#include <mw/mmr/backends/FileBackend.h>
#include <mw/db/LeafDB.h>

using namespace mmr;

MMR::Ptr MMRFactory::Build(
    const char prefix,
    const std::shared_ptr<libmw::IDBWrapper>& pDBWrapper,
    const std::unique_ptr<libmw::IDBBatch>& pBatch,
    const PruneList::Ptr& pPruneList,
    const MMRInfo& mmr_info,
    const FilePath& data_dir,
    const BitSet& unspent_leaf_indices,
    const std::vector<Leaf>& unspent_leaves,
    const std::vector<mw::Hash>& pruned_parent_hashes)
{
    // Calculate all non-compacted hashes
    std::vector<mw::Hash> hashes = CalcHashes(
        unspent_leaf_indices,
        unspent_leaves,
        pruned_parent_hashes
    );

    // Write hashes to file
    std::vector<uint8_t> bytes;
    bytes.reserve(hashes.size() * mw::Hash::size());
    for (const mw::Hash& hash : hashes) {
        bytes.insert(bytes.end(), hash.vec().begin(), hash.vec().end());
    }

    File(FileBackend::GetPath(data_dir, prefix, mmr_info.index))
        .Write(bytes);

    // Add leaves to database
    LeafDB(prefix, pDBWrapper.get(), pBatch.get())
        .Add(unspent_leaves);

    return std::make_shared<MMR>(
        FileBackend::Open(prefix, data_dir, mmr_info.index, pDBWrapper, pPruneList)
    );
}

std::vector<mw::Hash> MMRFactory::CalcHashes(
    const BitSet& unspent_leaf_indices,
    const std::vector<Leaf>& unspent_leaves,
    const std::vector<mw::Hash>& pruned_parent_hashes)
{
    assert(unspent_leaves.size() == unspent_leaf_indices.count());

    BitSet pruned_parent_indices = MMRUtil::CalcPrunedParents(unspent_leaf_indices);

    uint64_t num_nodes = unspent_leaf_indices.size() * 2;
    Index index = Index::At(0);

    BitSet hash_bitset(unspent_leaf_indices.size() * 2);
    std::vector<mw::Hash> ret;
    while (index.GetPosition() < num_nodes) {
        const uint64_t pos = index.GetPosition();
        if (index.IsLeaf() && unspent_leaf_indices.test(index.GetLeafIndex())) {
            size_t idx = unspent_leaf_indices.rank(index.GetLeafIndex());
            assert(unspent_leaves[idx].GetLeafIndex().Get() == index.GetLeafIndex());
            ret.push_back(unspent_leaves[idx].GetHash());
            hash_bitset.set(pos);
        } else if (pruned_parent_indices.test(pos)) {
            size_t idx = pruned_parent_indices.rank(pos);
            ret.push_back(pruned_parent_hashes[idx]);
            hash_bitset.set(pos);
        } else if (!index.IsLeaf()
            && hash_bitset.test(index.right_child_pos())
            && hash_bitset.test(index.left_child_pos())) {

            // Left child hash
            size_t left_idx = hash_bitset.rank(index.left_child_pos());
            const mw::Hash& left_hash = ret[left_idx];

            // Right child hash
            size_t right_idx = hash_bitset.rank(index.right_child_pos());
            const mw::Hash& right_hash = ret[right_idx];

            // Calculate and add hash
            ret.push_back(Node::CalcParentHash(index, left_hash, right_hash));
            hash_bitset.set(pos);
        }

        ++index;
    }

    return ret;
}