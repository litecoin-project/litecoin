// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <tinyformat.h>

#include <cmath>
#include <limits>

namespace {
CAmount GetMWEBFeeForWeight(uint32_t mweb_weight)
{
    if (uint64_t{mweb_weight} > uint64_t{std::numeric_limits<CAmount>::max() / BASE_MWEB_FEE}) {
        return std::numeric_limits<CAmount>::max();
    }

    return CAmount(mweb_weight) * BASE_MWEB_FEE;
}
} // namespace

CFeeRate::CFeeRate(const CAmount& nFeePaid, uint32_t num_bytes, uint32_t mweb_weight)
{
    const int64_t nSize{num_bytes};

    const CAmount mweb_fee = GetMWEBFeeForWeight(mweb_weight);
    if (mweb_fee > 0 && nFeePaid < mweb_fee) {
        nSatoshisPerK = 0;
    } else {
        CAmount ltc_fee = (nFeePaid - mweb_fee);
        if (nSize > 0)
            nSatoshisPerK = ltc_fee * 1000 / nSize;
        else
            nSatoshisPerK = 0;
    }

}

CAmount CFeeRate::GetFee(uint32_t num_bytes, uint32_t mweb_weight) const
{
    const int64_t nSize{num_bytes};

    // Be explicit that we're converting from a double to int64_t (CAmount) here.
    // We've previously had issues with the silent double->int64_t conversion.
    CAmount nFee{static_cast<CAmount>(std::ceil(nSatoshisPerK * nSize / 1000.0))};

    if (nFee == 0 && nSize != 0) {
        if (nSatoshisPerK > 0) nFee = CAmount(1);
        if (nSatoshisPerK < 0) nFee = CAmount(-1);
    }

    const CAmount mweb_fee = GetMWEBFeeForWeight(mweb_weight);
    if (nFee > 0 && mweb_fee > std::numeric_limits<CAmount>::max() - nFee) {
        return std::numeric_limits<CAmount>::max();
    }

    return nFee + mweb_fee;
}

std::string CFeeRate::ToString(const FeeEstimateMode& fee_estimate_mode) const
{
    switch (fee_estimate_mode) {
    case FeeEstimateMode::SAT_VB: return strprintf("%d.%03d %s/vB", nSatoshisPerK / 1000, nSatoshisPerK % 1000, CURRENCY_ATOM);
    default:                      return strprintf("%d.%08d %s/kvB", nSatoshisPerK / COIN, nSatoshisPerK % COIN, CURRENCY_UNIT);
    }
}
