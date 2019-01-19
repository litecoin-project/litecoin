// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparamsbase.h>

#include <tinyformat.h>
#include <util.h>

#include <assert.h>
#include <memory>

const std::string CBaseChainParams::MAIN = "main";
const std::string CBaseChainParams::TESTNET = "test";
const std::string CBaseChainParams::REGTEST = "regtest";
const std::string CBaseChainParams::SIMNET = "simnet";


void AppendParamsHelpMessages(std::string& strUsage, bool debugHelp)
{
    strUsage += HelpMessageGroup(_("Chain selection options:"));
    strUsage += HelpMessageOpt("-testnet", _("Use the test chain"));
    if (debugHelp) {
        strUsage += HelpMessageOpt("-regtest", "Enter regression test mode, which uses a special chain in which blocks can be solved instantly. "
                                   "This is intended for regression testing tools and app development.");
    }
}

/**
 * Main network
 */
class CBaseMainParams : public CBaseChainParams
{
public:
    CBaseMainParams()
    {
        nRPCPort = 9332;
    }
};

/**
 * Testnet (v3)
 */
class CBaseTestNetParams : public CBaseChainParams
{
public:
    CBaseTestNetParams()
    {
        nRPCPort = 19332;
        strDataDir = "testnet4";
    }
};

/*
 * Regression test
 */
class CBaseRegTestParams : public CBaseChainParams
{
public:
    CBaseRegTestParams()
    {
        nRPCPort = 19443;
        strDataDir = "regtest";
    }
};

/*
 * Simulation test */
class CBaseSimNetParams : public CBaseChainParams
{
public:
    CBaseSimNetParams()
    {
        nRPCPort = 18554;
        strDataDir = "simnet";
    }
};

static std::unique_ptr<CBaseChainParams> globalChainBaseParams;

const CBaseChainParams& BaseParams()
{
    assert(globalChainBaseParams);
    return *globalChainBaseParams;
}

std::unique_ptr<CBaseChainParams> CreateBaseChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CBaseChainParams>(new CBaseMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CBaseChainParams>(new CBaseTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CBaseChainParams>(new CBaseRegTestParams());
    else if (chain == CBaseChainParams::SIMNET)
        return std::unique_ptr<CBaseChainParams>(new CBaseSimNetParams());
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectBaseParams(const std::string& chain)
{
    globalChainBaseParams = CreateBaseChainParams(chain);
}

std::string ChainNameFromCommandLine()
{
    bool fRegTest = gArgs.GetBoolArg("-regtest", false);
    bool fTestNet = gArgs.GetBoolArg("-testnet", false);
    bool fSimNet = gArgs.GetBoolArg("-simnet", false);

    if ((fTestNet && fRegTest) || (fTestNet && fSimNet) || (fRegTest && fSimNet)
            || (fTestNet && fRegTest && fSimNet))
        throw std::runtime_error("Invalid combination of -regtest, -testnet and -simnet, only one option allowed.");
    if (fRegTest)
        return CBaseChainParams::REGTEST;
    if (fTestNet)
        return CBaseChainParams::TESTNET;
    if (fSimNet)
        return CBaseChainParams::SIMNET;

    return CBaseChainParams::MAIN;
}
