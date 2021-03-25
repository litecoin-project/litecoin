#include <catch.hpp>

#include <mw/mmr/LeafIndex.h>

using namespace mmr;

TEST_CASE("mmr::LeafIndex::GetLeafIndex")
{
    for (uint64_t i = 0; i < 1000; i++)
    {
        REQUIRE(LeafIndex::At(i).GetLeafIndex() == i);
    }
}

TEST_CASE("mmr::LeafIndex::GetNodeIndex")
{
    REQUIRE(LeafIndex::At(0).GetNodeIndex() == Index::At(0));
    REQUIRE(LeafIndex::At(1).GetNodeIndex() == Index::At(1));
    REQUIRE(LeafIndex::At(2).GetNodeIndex() == Index::At(3));
    REQUIRE(LeafIndex::At(3).GetNodeIndex() == Index::At(4));
    REQUIRE(LeafIndex::At(4).GetNodeIndex() == Index::At(7));
    REQUIRE(LeafIndex::At(5).GetNodeIndex() == Index::At(8));
    REQUIRE(LeafIndex::At(6).GetNodeIndex() == Index::At(10));
    REQUIRE(LeafIndex::At(7).GetNodeIndex() == Index::At(11));
    REQUIRE(LeafIndex::At(8).GetNodeIndex() == Index::At(15));
    REQUIRE(LeafIndex::At(9).GetNodeIndex() == Index::At(16));
    REQUIRE(LeafIndex::At(10).GetNodeIndex() == Index::At(18));
    REQUIRE(LeafIndex::At(11).GetNodeIndex() == Index::At(19));
    REQUIRE(LeafIndex::At(12).GetNodeIndex() == Index::At(22));
    REQUIRE(LeafIndex::At(13).GetNodeIndex() == Index::At(23));
    REQUIRE(LeafIndex::At(14).GetNodeIndex() == Index::At(25));
    REQUIRE(LeafIndex::At(15).GetNodeIndex() == Index::At(26));
    REQUIRE(LeafIndex::At(16).GetNodeIndex() == Index::At(31));
    REQUIRE(LeafIndex::At(17).GetNodeIndex() == Index::At(32));
    REQUIRE(LeafIndex::At(18).GetNodeIndex() == Index::At(34));
    REQUIRE(LeafIndex::At(19).GetNodeIndex() == Index::At(35));
    REQUIRE(LeafIndex::At(20).GetNodeIndex() == Index::At(38));
}

TEST_CASE("mmr::LeafIndex::GetPosition")
{
    REQUIRE(LeafIndex::At(0).GetPosition() == 0);
    REQUIRE(LeafIndex::At(1).GetPosition() == 1);
    REQUIRE(LeafIndex::At(2).GetPosition() == 3);
    REQUIRE(LeafIndex::At(3).GetPosition() == 4);
    REQUIRE(LeafIndex::At(4).GetPosition() == 7);
    REQUIRE(LeafIndex::At(5).GetPosition() == 8);
    REQUIRE(LeafIndex::At(6).GetPosition() == 10);
    REQUIRE(LeafIndex::At(7).GetPosition() == 11);
    REQUIRE(LeafIndex::At(8).GetPosition() == 15);
    REQUIRE(LeafIndex::At(9).GetPosition() == 16);
    REQUIRE(LeafIndex::At(10).GetPosition() == 18);
    REQUIRE(LeafIndex::At(11).GetPosition() == 19);
    REQUIRE(LeafIndex::At(12).GetPosition() == 22);
    REQUIRE(LeafIndex::At(13).GetPosition() == 23);
    REQUIRE(LeafIndex::At(14).GetPosition() == 25);
    REQUIRE(LeafIndex::At(15).GetPosition() == 26);
    REQUIRE(LeafIndex::At(16).GetPosition() == 31);
    REQUIRE(LeafIndex::At(17).GetPosition() == 32);
    REQUIRE(LeafIndex::At(18).GetPosition() == 34);
    REQUIRE(LeafIndex::At(19).GetPosition() == 35);
    REQUIRE(LeafIndex::At(20).GetPosition() == 38);
}