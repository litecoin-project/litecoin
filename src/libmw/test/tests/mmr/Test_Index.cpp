#include <catch.hpp>

#include <mw/mmr/Index.h>

using namespace mmr;

TEST_CASE("mmr::Index::GetHeight")
{
    REQUIRE(Index::At(0).GetHeight() == 0);
    REQUIRE(Index::At(1).GetHeight() == 0);
    REQUIRE(Index::At(2).GetHeight() == 1);
    REQUIRE(Index::At(3).GetHeight() == 0);
    REQUIRE(Index::At(4).GetHeight() == 0);
    REQUIRE(Index::At(5).GetHeight() == 1);
    REQUIRE(Index::At(6).GetHeight() == 2);
    REQUIRE(Index::At(7).GetHeight() == 0);
    REQUIRE(Index::At(8).GetHeight() == 0);
    REQUIRE(Index::At(9).GetHeight() == 1);
    REQUIRE(Index::At(10).GetHeight() == 0);
    REQUIRE(Index::At(11).GetHeight() == 0);
    REQUIRE(Index::At(12).GetHeight() == 1);
    REQUIRE(Index::At(13).GetHeight() == 2);
    REQUIRE(Index::At(14).GetHeight() == 3);
    REQUIRE(Index::At(15).GetHeight() == 0);
    REQUIRE(Index::At(16).GetHeight() == 0);
    REQUIRE(Index::At(17).GetHeight() == 1);
    REQUIRE(Index::At(18).GetHeight() == 0);
    REQUIRE(Index::At(19).GetHeight() == 0);
    REQUIRE(Index::At(20).GetHeight() == 1);
}

TEST_CASE("mmr::Index::GetLeafIndex")
{
    REQUIRE(Index::At(0).GetLeafIndex() == 0);
    REQUIRE(Index::At(1).GetLeafIndex() == 1);
    REQUIRE(Index::At(3).GetLeafIndex() == 2);
    REQUIRE(Index::At(4).GetLeafIndex() == 3);
    REQUIRE(Index::At(7).GetLeafIndex() == 4);
    REQUIRE(Index::At(8).GetLeafIndex() == 5);
    REQUIRE(Index::At(10).GetLeafIndex() == 6);
    REQUIRE(Index::At(11).GetLeafIndex() == 7);
    REQUIRE(Index::At(15).GetLeafIndex() == 8);
    REQUIRE(Index::At(16).GetLeafIndex() == 9);
    REQUIRE(Index::At(18).GetLeafIndex() == 10);
    REQUIRE(Index::At(19).GetLeafIndex() == 11);
}

TEST_CASE("mmr::Index::IsLeaf")
{
    REQUIRE(Index::At(0).IsLeaf());
    REQUIRE(Index::At(1).IsLeaf());
    REQUIRE(Index::At(3).IsLeaf());
    REQUIRE(Index::At(4).IsLeaf());
    REQUIRE(Index::At(7).IsLeaf());
    REQUIRE(Index::At(8).IsLeaf());
    REQUIRE(Index::At(10).IsLeaf());
    REQUIRE(Index::At(11).IsLeaf());
    REQUIRE(Index::At(15).IsLeaf());
    REQUIRE(Index::At(16).IsLeaf());
    REQUIRE(Index::At(18).IsLeaf());
    REQUIRE(Index::At(19).IsLeaf());

    REQUIRE_FALSE(Index::At(2).IsLeaf());
    REQUIRE_FALSE(Index::At(5).IsLeaf());
    REQUIRE_FALSE(Index::At(6).IsLeaf());
    REQUIRE_FALSE(Index::At(9).IsLeaf());
    REQUIRE_FALSE(Index::At(12).IsLeaf());
    REQUIRE_FALSE(Index::At(13).IsLeaf());
    REQUIRE_FALSE(Index::At(14).IsLeaf());
    REQUIRE_FALSE(Index::At(17).IsLeaf());
    REQUIRE_FALSE(Index::At(20).IsLeaf());
}

TEST_CASE("mmr::Index::GetNext")
{
    REQUIRE(Index::At(0).GetNext() == Index::At(1));
    REQUIRE(Index::At(1).GetNext() == Index::At(2));
    REQUIRE(Index::At(2).GetNext() == Index::At(3));
    REQUIRE(Index::At(3).GetNext() == Index::At(4));
    REQUIRE(Index::At(4).GetNext() == Index::At(5));
    REQUIRE(Index::At(5).GetNext() == Index::At(6));
    REQUIRE(Index::At(6).GetNext() == Index::At(7));
    REQUIRE(Index::At(7).GetNext() == Index::At(8));
    REQUIRE(Index::At(8).GetNext() == Index::At(9));
    REQUIRE(Index::At(9).GetNext() == Index::At(10));
    REQUIRE(Index::At(10).GetNext() == Index::At(11));
    REQUIRE(Index::At(11).GetNext() == Index::At(12));
    REQUIRE(Index::At(12).GetNext() == Index::At(13));
    REQUIRE(Index::At(13).GetNext() == Index::At(14));
    REQUIRE(Index::At(14).GetNext() == Index::At(15));
    REQUIRE(Index::At(15).GetNext() == Index::At(16));
    REQUIRE(Index::At(16).GetNext() == Index::At(17));
    REQUIRE(Index::At(17).GetNext() == Index::At(18));
    REQUIRE(Index::At(18).GetNext() == Index::At(19));
    REQUIRE(Index::At(19).GetNext() == Index::At(20));
    REQUIRE(Index::At(20).GetNext() == Index::At(21));
}

TEST_CASE("mmr::Index::GetParent")
{
    REQUIRE(Index::At(0).GetParent() == Index::At(2));
    REQUIRE(Index::At(1).GetParent() == Index::At(2));
    REQUIRE(Index::At(2).GetParent() == Index::At(6));
    REQUIRE(Index::At(3).GetParent() == Index::At(5));
    REQUIRE(Index::At(4).GetParent() == Index::At(5));
    REQUIRE(Index::At(5).GetParent() == Index::At(6));
    REQUIRE(Index::At(6).GetParent() == Index::At(14));
    REQUIRE(Index::At(7).GetParent() == Index::At(9));
    REQUIRE(Index::At(8).GetParent() == Index::At(9));
    REQUIRE(Index::At(9).GetParent() == Index::At(13));
    REQUIRE(Index::At(10).GetParent() == Index::At(12));
    REQUIRE(Index::At(11).GetParent() == Index::At(12));
    REQUIRE(Index::At(12).GetParent() == Index::At(13));
    REQUIRE(Index::At(13).GetParent() == Index::At(14));
    REQUIRE(Index::At(14).GetParent() == Index::At(30));
    REQUIRE(Index::At(15).GetParent() == Index::At(17));
    REQUIRE(Index::At(16).GetParent() == Index::At(17));
    REQUIRE(Index::At(17).GetParent() == Index::At(21));
    REQUIRE(Index::At(18).GetParent() == Index::At(20));
    REQUIRE(Index::At(19).GetParent() == Index::At(20));
    REQUIRE(Index::At(20).GetParent() == Index::At(21));
}

TEST_CASE("mmr::Index::GetSibling")
{
    REQUIRE(Index::At(0).GetSibling() == Index::At(1));
    REQUIRE(Index::At(1).GetSibling() == Index::At(0));
    REQUIRE(Index::At(2).GetSibling() == Index::At(5));
    REQUIRE(Index::At(3).GetSibling() == Index::At(4));
    REQUIRE(Index::At(4).GetSibling() == Index::At(3));
    REQUIRE(Index::At(5).GetSibling() == Index::At(2));
    REQUIRE(Index::At(6).GetSibling() == Index::At(13));
    REQUIRE(Index::At(7).GetSibling() == Index::At(8));
    REQUIRE(Index::At(8).GetSibling() == Index::At(7));
    REQUIRE(Index::At(9).GetSibling() == Index::At(12));
    REQUIRE(Index::At(10).GetSibling() == Index::At(11));
    REQUIRE(Index::At(11).GetSibling() == Index::At(10));
    REQUIRE(Index::At(12).GetSibling() == Index::At(9));
    REQUIRE(Index::At(13).GetSibling() == Index::At(6));
    REQUIRE(Index::At(14).GetSibling() == Index::At(29));
    REQUIRE(Index::At(15).GetSibling() == Index::At(16));
    REQUIRE(Index::At(16).GetSibling() == Index::At(15));
    REQUIRE(Index::At(17).GetSibling() == Index::At(20));
    REQUIRE(Index::At(18).GetSibling() == Index::At(19));
    REQUIRE(Index::At(19).GetSibling() == Index::At(18));
    REQUIRE(Index::At(20).GetSibling() == Index::At(17));
}

TEST_CASE("mmr::Index::GetLeftChild")
{
    REQUIRE(Index::At(2).GetLeftChild() == Index::At(0));
    REQUIRE(Index::At(5).GetLeftChild() == Index::At(3));
    REQUIRE(Index::At(6).GetLeftChild() == Index::At(2));
    REQUIRE(Index::At(9).GetLeftChild() == Index::At(7));
    REQUIRE(Index::At(12).GetLeftChild() == Index::At(10));
    REQUIRE(Index::At(13).GetLeftChild() == Index::At(9));
    REQUIRE(Index::At(14).GetLeftChild() == Index::At(6));
    REQUIRE(Index::At(17).GetLeftChild() == Index::At(15));
    REQUIRE(Index::At(20).GetLeftChild() == Index::At(18));
}

TEST_CASE("mmr::Index::GetRightChild")
{
    REQUIRE(Index::At(2).GetRightChild() == Index::At(1));
    REQUIRE(Index::At(5).GetRightChild() == Index::At(4));
    REQUIRE(Index::At(6).GetRightChild() == Index::At(5));
    REQUIRE(Index::At(9).GetRightChild() == Index::At(8));
    REQUIRE(Index::At(12).GetRightChild() == Index::At(11));
    REQUIRE(Index::At(13).GetRightChild() == Index::At(12));
    REQUIRE(Index::At(14).GetRightChild() == Index::At(13));
    REQUIRE(Index::At(17).GetRightChild() == Index::At(16));
    REQUIRE(Index::At(20).GetRightChild() == Index::At(19));
}