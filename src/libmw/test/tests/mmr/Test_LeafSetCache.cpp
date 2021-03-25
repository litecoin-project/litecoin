#include <catch.hpp>

#include <mw/mmr/LeafSet.h>
#include <mw/crypto/Hasher.h>
#include <mw/file/ScopedFileRemover.h>

#include <test_framework/TestUtil.h>

TEST_CASE("mmr::LeafSetCache")
{
	FilePath temp_dir = test::TestUtil::GetTempDir();
	ScopedFileRemover remover(temp_dir); // Removes the directory when this goes out of scope.

	{
		mmr::LeafSet::Ptr pLeafset = mmr::LeafSet::Open(temp_dir, 0);

		pLeafset->Add(mmr::LeafIndex::At(0));
		pLeafset->Add(mmr::LeafIndex::At(1));
		pLeafset->Add(mmr::LeafIndex::At(2));
		pLeafset->Add(mmr::LeafIndex::At(4));

		// Flush to disk
		pLeafset->Flush(1);
	}

	{
		// Reload from disk
		mmr::LeafSet::Ptr pLeafset = mmr::LeafSet::Open(temp_dir, 1);

		// Create cache and validate
		mmr::LeafSetCache::Ptr pCache = std::make_shared<mmr::LeafSetCache>(pLeafset);
		REQUIRE(pCache->GetNextLeafIdx().Get() == 5);
		REQUIRE(pCache->Root() == Hashed({ 0b11101000 }));

		// Test with 2 layers of caches to cover all scenarios
		mmr::LeafSetCache::Ptr pCache2 = std::make_shared<mmr::LeafSetCache>(pCache);
		pCache2->Add(mmr::LeafIndex::At(5));
		pCache2->Remove(mmr::LeafIndex::At(2));

		// pCache2 should contain the updates, but pCache and pLeafset should remain unchanged.
		REQUIRE(pLeafset->GetNextLeafIdx().Get() == 5);
		REQUIRE(pLeafset->Root() == Hashed({ 0b11101000 }));
		REQUIRE(pCache->GetNextLeafIdx().Get() == 5);
		REQUIRE(pCache->Root() == Hashed({ 0b11101000 }));
		REQUIRE(pCache2->GetNextLeafIdx().Get() == 6);
		REQUIRE(pCache2->Root() == Hashed({ 0b11001100 }));
		
		// Flush pCache2 to pCache. pCache should be updated, but pLeafset should remain unchanged.
		pCache2->Flush(0);
		REQUIRE(pLeafset->GetNextLeafIdx().Get() == 5);
		REQUIRE(pLeafset->Root() == Hashed({ 0b11101000 }));
		REQUIRE(pCache->GetNextLeafIdx().Get() == 6);
		REQUIRE(pCache->Root() == Hashed({ 0b11001100 }));
		REQUIRE(pCache2->GetNextLeafIdx().Get() == 6);
		REQUIRE(pCache2->Root() == Hashed({ 0b11001100 }));
	}
}