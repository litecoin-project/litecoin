// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/mmr/LeafSet.h>
#include <mw/crypto/Hasher.h>

#include <test_framework/TestMWEB.h>

#include <algorithm>

#ifndef WIN32
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#endif

BOOST_FIXTURE_TEST_SUITE(TestMMRLeafSet, MWEBTestingSetup)

#ifndef WIN32
static size_t CountOpenFileDescriptors()
{
    const long configured_max = sysconf(_SC_OPEN_MAX);
    const int scan_limit = configured_max > 0 ? std::min<long>(configured_max, 4096) : 1024;
    size_t count = 0;

    for (int fd = 0; fd < scan_limit; ++fd) {
        errno = 0;
        if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) {
            ++count;
        }
    }

    return count;
}
#endif

BOOST_AUTO_TEST_CASE(LeafSetTest)
{
    {
        LeafSet::Ptr pLeafset = LeafSet::Open(GetDataDir(), 0);

        BOOST_REQUIRE(pLeafset->GetNextLeafIdx().Get() == 0);
        BOOST_REQUIRE(!pLeafset->Contains(mmr::LeafIndex::At(0)));
        BOOST_REQUIRE(!pLeafset->Contains(mmr::LeafIndex::At(1)));
        BOOST_REQUIRE(!pLeafset->Contains(mmr::LeafIndex::At(2)));
        BOOST_REQUIRE(pLeafset->Root() == Hashed(std::vector<uint8_t>{ }));

        pLeafset->Add(mmr::LeafIndex::At(0));
        BOOST_REQUIRE(pLeafset->Contains(mmr::LeafIndex::At(0)));
        BOOST_REQUIRE(pLeafset->GetNextLeafIdx().Get() == 1);
        BOOST_REQUIRE(pLeafset->Root() == Hashed({ 0b10000000 }));

        pLeafset->Add(mmr::LeafIndex::At(1));
        BOOST_REQUIRE(pLeafset->Contains(mmr::LeafIndex::At(1)));
        BOOST_REQUIRE(pLeafset->GetNextLeafIdx().Get() == 2);
        BOOST_REQUIRE(pLeafset->Root() == Hashed({ 0b11000000 }));

        pLeafset->Add(mmr::LeafIndex::At(2));
        BOOST_REQUIRE(pLeafset->Contains(mmr::LeafIndex::At(2)));
        BOOST_REQUIRE(pLeafset->GetNextLeafIdx().Get() == 3);
        BOOST_REQUIRE(pLeafset->Root() == Hashed({ 0b11100000 }));

        pLeafset->Remove(mmr::LeafIndex::At(1));
        BOOST_REQUIRE(!pLeafset->Contains(mmr::LeafIndex::At(1)));
        BOOST_REQUIRE(pLeafset->GetNextLeafIdx().Get() == 3);
        BOOST_REQUIRE(pLeafset->Root() == Hashed({ 0b10100000 }));

        pLeafset->Rewind(2, { mmr::LeafIndex::At(1) });
        BOOST_REQUIRE(pLeafset->GetNextLeafIdx().Get() == 2);
        BOOST_REQUIRE(pLeafset->Root() == Hashed({ 0b11000000 }));

        // Flush to disk and validate
        pLeafset->Flush(1);
        BOOST_REQUIRE(pLeafset->GetNextLeafIdx().Get() == 2);
        BOOST_REQUIRE(pLeafset->Root() == Hashed({ 0b11000000 }));
    }

    {
        // Reload from disk and validate
        LeafSet::Ptr pLeafset = LeafSet::Open(GetDataDir(), 1);
        BOOST_REQUIRE(pLeafset->GetNextLeafIdx().Get() == 2);
        BOOST_REQUIRE(pLeafset->Root() == Hashed({ 0b11000000 }));
    }
}

#ifndef WIN32
BOOST_AUTO_TEST_CASE(LeafSetFlushClosesFileDescriptors)
{
    LeafSet::Ptr pLeafset = LeafSet::Open(GetDataDir(), 0);
    const size_t initial_fds = CountOpenFileDescriptors();

    for (uint32_t file_index = 1; file_index <= 32; ++file_index) {
        pLeafset->Add(mmr::LeafIndex::At(file_index - 1));
        pLeafset->Flush(file_index);
    }

    BOOST_CHECK_LE(CountOpenFileDescriptors(), initial_fds + 1);
}

BOOST_AUTO_TEST_CASE(FailedCopyClosesInputFileDescriptor)
{
    const FilePath root(GetDataDir());
    File source(root.GetChild("copy_source.dat"));
    source.Create();
    source.Write({0x01});

    const FilePath invalid_destination = root.GetChild("missing").GetChild("copy.dat");
    const size_t initial_fds = CountOpenFileDescriptors();
    for (int attempt = 0; attempt < 32; ++attempt) {
        BOOST_CHECK_THROW(source.CopyTo(invalid_destination), FileException);
    }

    BOOST_CHECK_EQUAL(CountOpenFileDescriptors(), initial_fds);
}
#endif

BOOST_AUTO_TEST_SUITE_END()
