#include <catch.hpp>

#include <mw/crypto/Random.h>
#include <mw/mmr/Leaf.h>
#include <mw/mmr/MMRFactory.h>
#include <mw/mmr/MMRUtil.h>

using namespace mmr;

static std::vector<Leaf> RandomLeaves(const BitSet& leafset)
{
    std::vector<Leaf> leaves;
    for (uint64_t leaf_idx = 0; leaf_idx < leafset.size(); leaf_idx++) {
        if (leafset.test(leaf_idx)) {
            leaves.push_back(Leaf::Create(LeafIndex::At(leaf_idx), Random::CSPRNG<20>().vec()));
        }
    }
    return leaves;
}

static std::vector<mw::Hash> RandomHashes(const uint64_t num_hashes)
{
    std::vector<mw::Hash> hashes(num_hashes);
    for (uint64_t i = 0; i < num_hashes; i++) {
        hashes[i] = Random::CSPRNG<32>().GetBigInt();
    }
    return hashes;
}

TEST_CASE("mmr::MMRFactory::CalcHashes")
{
    size_t num_leaves = 50;
    BitSet unspent_leaf_indices(num_leaves);
    unspent_leaf_indices.set(2);
    unspent_leaf_indices.set(9);
    unspent_leaf_indices.set(26);
    unspent_leaf_indices.set(27);
    for (size_t i = 30; i < num_leaves; i++) {
        unspent_leaf_indices.set(i);
    }

    std::vector<Leaf> leaves = RandomLeaves(unspent_leaf_indices);

    BitSet pruned_parent_indices = MMRUtil::CalcPrunedParents(unspent_leaf_indices);
    REQUIRE(pruned_parent_indices.str() == "0010100000000101000010000000100000000000000001001000000100000000000000000000000000000000000000000000");
    std::vector<mw::Hash> pruned_parent_hashes = RandomHashes(pruned_parent_indices.count());

    std::vector<mw::Hash> hashes = MMRFactory::CalcHashes(unspent_leaf_indices, leaves, pruned_parent_hashes);
    REQUIRE(hashes.size() == 63);
    REQUIRE(hashes[0] == pruned_parent_hashes[0]);
    REQUIRE(hashes[61] == leaves[23].GetHash());

    // Finish these assertions
}