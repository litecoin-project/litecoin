#pragma once

#include <mw/models/crypto/BigInteger.h>

#include <dbwrapper.h>
#include <boost/test/unit_test.hpp>
#include <random.h>
#include <test/util/setup_common.h>

template<size_t NUM_BYTES>
std::vector<uint8_t> RandomBytes()
{
    std::vector<uint8_t> bytes(NUM_BYTES);
    size_t index = 0;
    while (index < NUM_BYTES) {
        size_t num_bytes = std::min(NUM_BYTES - index, (size_t)32);
        GetStrongRandBytes(Span{bytes.data() + index, num_bytes});
        index += num_bytes;
    }
    return bytes;
}

template<size_t NUM_BYTES>
BigInt<NUM_BYTES> RandomBigInt()
{
    return BigInt<NUM_BYTES>(RandomBytes<NUM_BYTES>());
}

struct MWEBTestingSetup : public BasicTestingSetup
{
    explicit MWEBTestingSetup()
        : BasicTestingSetup(CBaseChainParams::MAIN)
    {
        m_db = std::make_unique<CDBWrapper>(m_path_root / "db", 1 << 15);
    }

    virtual ~MWEBTestingSetup() = default;

    CDBWrapper* GetDB() { return m_db.get(); }

private:
    std::unique_ptr<CDBWrapper> m_db;
};
