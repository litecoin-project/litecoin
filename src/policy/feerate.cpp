// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/feerate.h>

#include <tinyformat.h>

#include <limits>

namespace {
static constexpr CAmount BASE_MWEB_FEE = 100;

CAmount GetMWEBFeeForWeight(uint64_t mweb_weight)
{
    assert(mweb_weight <= uint64_t(std::numeric_limits<int64_t>::max()));
    if (mweb_weight > uint64_t(std::numeric_limits<CAmount>::max() / BASE_MWEB_FEE)) {
        return std::numeric_limits<CAmount>::max();
    }

    return CAmount(mweb_weight) * BASE_MWEB_FEE;
}
} // namespace

CFeeRate::CFeeRate(const CAmount& nFeePaid, size_t nBytes_, uint64_t mweb_weight)
    : m_nFeePaid(nFeePaid), m_nBytes(nBytes_), m_weight(mweb_weight)
{
    assert(nBytes_ <= uint64_t(std::numeric_limits<int64_t>::max()));
    assert(mweb_weight <= uint64_t(std::numeric_limits<int64_t>::max()));

    const CAmount mweb_fee = GetMWEBFeeForWeight(mweb_weight);
    if (mweb_fee > 0 && nFeePaid < mweb_fee) {
        nSatoshisPerK = 0;
    } else {
        CAmount ltc_fee = (nFeePaid - mweb_fee);

        int64_t nSize = int64_t(nBytes_);
        if (nSize > 0)
            nSatoshisPerK = ltc_fee * 1000 / nSize;
        else
            nSatoshisPerK = 0;
    }
}

CAmount CFeeRate::GetFee(size_t nBytes_) const
{
    assert(nBytes_ <= uint64_t(std::numeric_limits<int64_t>::max()));
    int64_t nSize = int64_t(nBytes_);

    CAmount nFee = nSatoshisPerK * nSize / 1000;

    if (nFee == 0 && nSize != 0) {
        if (nSatoshisPerK > 0)
            nFee = CAmount(1);
        if (nSatoshisPerK < 0)
            nFee = CAmount(-1);
    }

    return nFee;
}

CAmount CFeeRate::GetMWEBFee(uint64_t mweb_weight) const
{
    assert(mweb_weight <= uint64_t(std::numeric_limits<int64_t>::max()));
    return GetMWEBFeeForWeight(mweb_weight);
}

CAmount CFeeRate::GetTotalFee(size_t nBytes, uint64_t mweb_weight) const
{
    const CAmount byte_fee = GetFee(nBytes);
    const CAmount mweb_fee = GetMWEBFee(mweb_weight);
    if (byte_fee > 0 && mweb_fee > std::numeric_limits<CAmount>::max() - byte_fee) {
        return std::numeric_limits<CAmount>::max();
    }

    return byte_fee + mweb_fee;
}

bool CFeeRate::MeetsFeePerK(const CAmount& min_fee_per_k) const
{
    // (mweb_weight * BASE_MWEB_FEE) litoshis are required as fee for MWEB transactions.
    // Anything beyond that can be used to calculate nSatoshisPerK.
    const CAmount mweb_fee = GetMWEBFee(m_weight);
    if (m_weight > 0 && m_nFeePaid < mweb_fee) {
        return false;
    }

    // MWEB-to-MWEB transactions don't have a size to calculate nSatoshisPerK.
    // Since we got this far, we know the transaction meets the minimum MWEB fee, so return true.
    if (m_nBytes == 0 && m_weight > 0) {
        return true;
    }

    return nSatoshisPerK >= min_fee_per_k;
}

std::string CFeeRate::ToString(const FeeEstimateMode& fee_estimate_mode) const
{
    switch (fee_estimate_mode) {
    case FeeEstimateMode::SAT_VB: return strprintf("%d.%03d %s/vB", nSatoshisPerK / 1000, nSatoshisPerK % 1000, CURRENCY_ATOM);
    default:                      return strprintf("%d.%08d %s/kvB", nSatoshisPerK / COIN, nSatoshisPerK % COIN, CURRENCY_UNIT);
    }
}
