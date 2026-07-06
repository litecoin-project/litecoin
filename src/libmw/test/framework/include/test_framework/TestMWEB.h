#pragma once

#include <dbwrapper.h>
#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>

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
