#include <catch.hpp>

#include <mw/mmr/LeafSet.h>
#include <mw/crypto/Hasher.h>
#include <mw/file/ScopedFileRemover.h>

#include <test_framework/TestUtil.h>

TEST_CASE("mmr::LeafSet")
{
	FilePath temp_dir = test::TestUtil::GetTempDir();
	ScopedFileRemover remover(temp_dir); // Removes the directory when this goes out of scope.

	{
		mmr::LeafSet::Ptr pLeafset = mmr::LeafSet::Open(temp_dir, 0);

		REQUIRE(pLeafset->GetNextLeafIdx().GetLeafIndex() == 0);
		REQUIRE_FALSE(pLeafset->Contains(mmr::LeafIndex::At(0)));
		REQUIRE_FALSE(pLeafset->Contains(mmr::LeafIndex::At(1)));
		REQUIRE_FALSE(pLeafset->Contains(mmr::LeafIndex::At(2)));
		REQUIRE(pLeafset->Root() == Hashed(std::vector<uint8_t>{ }));

		pLeafset->Add(mmr::LeafIndex::At(0));
		REQUIRE(pLeafset->Contains(mmr::LeafIndex::At(0)));
		REQUIRE(pLeafset->GetNextLeafIdx().GetLeafIndex() == 1);
		REQUIRE(pLeafset->Root() == Hashed({ 0b10000000 }));

		pLeafset->Add(mmr::LeafIndex::At(1));
		REQUIRE(pLeafset->Contains(mmr::LeafIndex::At(1)));
		REQUIRE(pLeafset->GetNextLeafIdx().GetLeafIndex() == 2);
		REQUIRE(pLeafset->Root() == Hashed({ 0b11000000 }));

		pLeafset->Add(mmr::LeafIndex::At(2));
		REQUIRE(pLeafset->Contains(mmr::LeafIndex::At(2)));
		REQUIRE(pLeafset->GetNextLeafIdx().GetLeafIndex() == 3);
		REQUIRE(pLeafset->Root() == Hashed({ 0b11100000 }));

		pLeafset->Remove(mmr::LeafIndex::At(1));
		REQUIRE_FALSE(pLeafset->Contains(mmr::LeafIndex::At(1)));
		REQUIRE(pLeafset->GetNextLeafIdx().GetLeafIndex() == 3);
		REQUIRE(pLeafset->Root() == Hashed({ 0b10100000 }));

		pLeafset->Rewind(2, { mmr::LeafIndex::At(1) });
		REQUIRE(pLeafset->GetNextLeafIdx().GetLeafIndex() == 2);
		REQUIRE(pLeafset->Root() == Hashed({ 0b11000000 }));

		// Flush to disk and validate
		pLeafset->Flush(1);
		REQUIRE(pLeafset->GetNextLeafIdx().GetLeafIndex() == 2);
		REQUIRE(pLeafset->Root() == Hashed({ 0b11000000 }));
	}

	{
		// Reload from disk and validate
		mmr::LeafSet::Ptr pLeafset = mmr::LeafSet::Open(temp_dir, 1);
		REQUIRE(pLeafset->GetNextLeafIdx().GetLeafIndex() == 2);
		REQUIRE(pLeafset->Root() == Hashed({ 0b11000000 }));
	}
}