#pragma once

#include <mw/models/crypto/BigInteger.h>

#include <boost/test/unit_test.hpp>
#include <mweb/mweb_db.h>
#include <random.h>
#include <test/util/setup_common.h>

template<size_t NUM_BYTES>
std::vector<uint8_t> RandomBytes()
{
    std::vector<uint8_t> bytes(NUM_BYTES);
    size_t index = 0;
    while (index < NUM_BYTES) {
        size_t num_bytes = std::min(NUM_BYTES - index, (size_t)32);
        GetStrongRandBytes(bytes.data() + index, num_bytes);
        index += num_bytes;
    }
    return bytes;
}

template<size_t NUM_BYTES>
BigInt<NUM_BYTES> RandomBigInt()
{
    return BigInt<NUM_BYTES>(RandomBytes<NUM_BYTES>());
}

struct MWEBTestingSetup : public BasicTestingSetup {
    explicit MWEBTestingSetup()
        : BasicTestingSetup(CBaseChainParams::MAIN)
    {
        m_db = std::make_unique<CDBWrapper>(GetDataDir() / "db", 1 << 15);
        m_mweb_db = std::make_shared<MWEB::DBWrapper>(m_db.get());
    }

    virtual ~MWEBTestingSetup() = default;

    mw::DBWrapper::Ptr GetDB() { return m_mweb_db; }

private:
    std::unique_ptr<CDBWrapper> m_db;
    std::shared_ptr<mw::DBWrapper> m_mweb_db;
};
