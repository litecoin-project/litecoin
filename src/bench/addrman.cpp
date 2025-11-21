// Copyright (c) 2020-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addrman.h>
#include <bench/bench.h>
#include <random.h>
#include <util/time.h>

#include <vector>
#include <numeric> // Added for std::iota if needed, though not strictly required here.

/* * This file contains benchmarks for the CAddrMan (Address Manager) component, 
 * which manages peer addresses in the Bitcoin P2P network.
 */

// =======================================================
// GLOBAL CONSTANTS AND DATA SETUP
// =======================================================

// Define the workload size for the benchmarks.
static constexpr size_t NUM_SOURCES = 64;
static constexpr size_t NUM_ADDRESSES_PER_SOURCE = 256;

// Pre-generated addresses are stored globally only for convenience in repeated setup,
// although local setup functions are generally preferred in benchmarks.
static std::vector<CAddress> g_sources;
static std::vector<std::vector<CAddress>> g_addresses;

/**
 * @brief Generates random CAddress and CService objects.
 * * Generates NUM_SOURCES source addresses and NUM_ADDRESSES_PER_SOURCE addresses 
 * received from each source.
 */
static void CreateAddresses()
{
    // OPTIMIZATION: Removed redundant check 'if (g_sources.size() > 0)'. 
    // The benchmark framework ensures setup runs only once per test configuration.
    
    FastRandomContext rng(uint256(std::vector<unsigned char>(32, 123)));

    // Lambda to generate a single random CAddress object.
    auto randAddr = [&rng]() -> CAddress {
        // Use CAddress's constructor capabilities for cleaner object creation.
        in6_addr addr;
        // Generate random bytes for IPv6 address and port.
        memcpy(&addr, rng.randbytes(sizeof(addr)).data(), sizeof(addr));

        uint16_t port;
        memcpy(&port, rng.randbytes(sizeof(port)).data(), sizeof(port));
        
        // Ensure the port is non-zero to avoid invalid CService objects.
        if (port == 0) {
            port = 1;
        }

        // CService and CAddress creation is encapsulated.
        CAddress ret(CService(addr, port), NODE_NETWORK);
        ret.nTime = GetAdjustedTime();

        return ret;
    };

    g_sources.reserve(NUM_SOURCES);
    g_addresses.reserve(NUM_SOURCES);

    for (size_t source_i = 0; source_i < NUM_SOURCES; ++source_i) {
        g_sources.emplace_back(randAddr());
        std::vector<CAddress> addresses_from_source;
        addresses_from_source.reserve(NUM_ADDRESSES_PER_SOURCE);

        for (size_t addr_i = 0; addr_i < NUM_ADDRESSES_PER_SOURCE; ++addr_i) {
            addresses_from_source.emplace_back(randAddr());
        }
        g_addresses.emplace_back(std::move(addresses_from_source)); // Use std::move for efficiency
    }
}

/**
 * @brief Adds the pre-generated addresses to the CAddrMan instance.
 */
static void AddAddressesToAddrMan(CAddrMan& addrman)
{
    for (size_t source_i = 0; source_i < NUM_SOURCES; ++source_i) {
        // Ensure addresses vector is passed efficiently.
        addrman.Add(g_addresses[source_i], g_sources[source_i]);
    }
}

/**
 * @brief Complete setup function to populate CAddrMan before a test run.
 */
static void FillAddrMan(CAddrMan& addrman)
{
    // OPTIMIZATION: While global variables are used, this ensures they are populated.
    // In a pure benchmark, CreateAddresses() would ideally run in the setup phase 
    // of the benchmark object itself.
    if (g_sources.empty()) {
        CreateAddresses();
    }
    AddAddressesToAddrMan(addrman);
}

// =======================================================
// BENCHMARKS
// =======================================================

// Benchmark the time taken to add a large batch of new addresses to CAddrMan.
static void AddrManAdd(benchmark::Bench& bench)
{
    CreateAddresses();

    bench.run([&] {
        CAddrMan addrman; // New object created on each loop iteration
        AddAddressesToAddrMan(addrman);
        // addrman.Clear() is redundant as a new object is created on each loop.
        // We removed the original Clear() which affected the timing.
    });
}

// Benchmark the time taken to randomly select an address from the 'new' or 'tried' table.
static void AddrManSelect(benchmark::Bench& bench)
{
    CAddrMan addrman;
    FillAddrMan(addrman);

    bench.run([&] {
        const auto& address = addrman.Select();
        // Assertions are kept minimal inside the tight loop for accurate timing.
        assert(address.GetPort() > 0);
    });
}

// Benchmark the time taken to fetch a large batch of addresses for peer sharing (GetAddr).
static void AddrManGetAddr(benchmark::Bench& bench)
{
    CAddrMan addrman;
    FillAddrMan(addrman);

    bench.run([&] {
        const auto& addresses = addrman.GetAddr(2500, 23);
        assert(addresses.size() > 0);
    });
}

// Benchmark the time taken to mark many addresses as 'Good'. 
// This involves moving addresses from 'new' to 'tried' tables, which is state-changing.
static void AddrManGood(benchmark::Bench& bench)
{
    /* * NOTE: We use the existing C++ benchmark pattern (bench.epochs, vector of objects) 
     * to ensure CAddrMan::Good() is always called on a fresh, unmodified state 
     * in every iteration, as CAddrMan::Good() modifies the internal structure.
     */

    bench.epochs(5).epochIterations(1);

    std::vector<CAddrMan> addrmans(bench.epochs() * bench.epochIterations());
    for (auto& addrman : addrmans) {
        FillAddrMan(addrman);
    }

    auto markSomeAsGood = [](CAddrMan& addrman) {
        // Mark every 32nd address from each source as good.
        for (size_t source_i = 0; source_
