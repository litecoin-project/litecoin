#include <catch.hpp>

#include <mw/mmr/MMRUtil.h>
#include <unordered_set>

using namespace mmr;

#define REQUIRE_NEXT(iter, expected_pos) \
    REQUIRE(iter.Next()); \
    REQUIRE(iter.GetPosition() == expected_pos);

TEST_CASE("mmr::SiblingIter")
{
    // Height 0
    {
        SiblingIter iter(0, mmr::Index::At(22));
        REQUIRE_NEXT(iter, 0);
        REQUIRE_NEXT(iter, 1);
        REQUIRE_NEXT(iter, 3);
        REQUIRE_NEXT(iter, 4);
        REQUIRE_NEXT(iter, 7);
        REQUIRE_NEXT(iter, 8);
        REQUIRE_NEXT(iter, 10);
        REQUIRE_NEXT(iter, 11);
        REQUIRE_NEXT(iter, 15);
        REQUIRE_NEXT(iter, 16);
        REQUIRE_NEXT(iter, 18);
        REQUIRE_NEXT(iter, 19);
        REQUIRE_NEXT(iter, 22);
        REQUIRE_FALSE(iter.Next());
    }

    // Height 1
    {
        SiblingIter iter(1, mmr::Index::At(84));
        REQUIRE_NEXT(iter, 2);
        REQUIRE_NEXT(iter, 5);
        REQUIRE_NEXT(iter, 9);
        REQUIRE_NEXT(iter, 12);
        REQUIRE_NEXT(iter, 17);
        REQUIRE_NEXT(iter, 20);
        REQUIRE_NEXT(iter, 24);
        REQUIRE_NEXT(iter, 27);
        REQUIRE_NEXT(iter, 33);
        REQUIRE_NEXT(iter, 36);
        REQUIRE_NEXT(iter, 40);
        REQUIRE_NEXT(iter, 43);
        REQUIRE_NEXT(iter, 48);
        REQUIRE_NEXT(iter, 51);
        REQUIRE_NEXT(iter, 55);
        REQUIRE_NEXT(iter, 58);
        REQUIRE_NEXT(iter, 65);
        REQUIRE_NEXT(iter, 68);
        REQUIRE_NEXT(iter, 72);
        REQUIRE_NEXT(iter, 75);
        REQUIRE_NEXT(iter, 80);
        REQUIRE_NEXT(iter, 83);
        REQUIRE_FALSE(iter.Next());
    }

    // Height 2
    {
        SiblingIter iter(2, mmr::Index::At(100));
        REQUIRE_NEXT(iter, 6);
        REQUIRE_NEXT(iter, 13);
        REQUIRE_NEXT(iter, 21);
        REQUIRE_NEXT(iter, 28);
        REQUIRE_NEXT(iter, 37);
        REQUIRE_NEXT(iter, 44);
        REQUIRE_NEXT(iter, 52);
        REQUIRE_NEXT(iter, 59);
        REQUIRE_NEXT(iter, 69);
        REQUIRE_NEXT(iter, 76);
        REQUIRE_NEXT(iter, 84);
        REQUIRE_NEXT(iter, 91);
        REQUIRE_NEXT(iter, 100);
        REQUIRE_FALSE(iter.Next());
    }

    // Thorough check of positions 0-2500
    {
        mmr::Index last_node = mmr::Index::At(2500);
        std::unordered_set<uint64_t> nodes_found;
        for (uint8_t height = 0; height <= 12; height++) {
            SiblingIter iter(height, last_node);

            while (iter.Next()) {
                REQUIRE(nodes_found.count(iter.GetPosition()) == 0);
                REQUIRE(mmr::Index::At(iter.GetPosition()).GetHeight() == height);
                nodes_found.insert(iter.GetPosition());
            }
        }

        for (uint64_t i = 0; i <= last_node.GetPosition(); i++) {
            REQUIRE(nodes_found.count(i) == 1);
        }
    }
}

TEST_CASE("mmr::MMRUtil::BuildCompactBitSet")
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

    BitSet compactable_node_indices = mmr::MMRUtil::BuildCompactBitSet(num_leaves, unspent_leaf_indices);
    REQUIRE(compactable_node_indices.str() == "1100000111111000001100111111000111111111111110110000011000000000000000000000000000000000000000000000");
    REQUIRE(compactable_node_indices.count() == 34);
}

TEST_CASE("mmr::MMRUtil::DiffCompactBitSet")
{
    BitSet prev_compact(10);
    prev_compact.set(0, 5, true);

    BitSet new_compact(20);
    new_compact.set(0, 5, true);
    new_compact.set(8, 10, true);

    BitSet diff = mmr::MMRUtil::DiffCompactBitSet(prev_compact, new_compact);

    REQUIRE(diff.size() == 15);
    REQUIRE(diff.str() == "000111111111100");
}

TEST_CASE("mmr::MMRUtil::CalcPrunedParents")
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

    BitSet pruned_parent_hashes = mmr::MMRUtil::CalcPrunedParents(unspent_leaf_indices);
    REQUIRE(pruned_parent_hashes.str() == "0010100000000101000010000000100000000000000001001000000100000000000000000000000000000000000000000000");
}