#pragma once

#include <consensus/amount.h>
#include <script/address.h>
#include <numeric>
#include <vector>

namespace wallet {

struct CRecipient
{
    GenericAddress receiver;
    CAmount nAmount;
    bool fSubtractFeeFromAmount;

    bool operator==(const CRecipient& rhs) const noexcept
    {
        return receiver == rhs.receiver && nAmount == rhs.nAmount && fSubtractFeeFromAmount == rhs.fSubtractFeeFromAmount;
    }

    bool IsMWEB() const noexcept
    {
        return receiver.IsMWEB();
    }

    const StealthAddress& GetMWEBAddress() const noexcept
    {
        return receiver.GetMWEBAddress();
    }

    const CScript& GetScript() const noexcept
    {
        return receiver.GetScript();
    }
};

class CRecipients
{
    std::vector<CRecipient> m_vec;

public:
    CRecipients() = default;
    CRecipients(std::vector<CRecipient> vec)
        : m_vec(std::move(vec)) {}

    const std::vector<CRecipient>& operator*() const noexcept { return m_vec; }
    const std::vector<CRecipient>* operator->() const noexcept { return &m_vec; }
    CRecipient& operator[](size_t pos) { return m_vec[pos]; }
    size_t size() const noexcept { return m_vec.size(); }
    auto cbegin() const noexcept { return m_vec.cbegin(); }
    auto cend() const noexcept { return m_vec.cend(); }
    std::vector<CRecipient>& get_mut() noexcept { return m_vec; }

    void push_back(CRecipient recipient) noexcept { m_vec.push_back(std::move(recipient)); }
    void insert_at(const size_t position, CRecipient recipient)
    {
        assert(position <= m_vec.size());
        m_vec.insert(m_vec.begin() + position, std::move(recipient));
    }

    // Calculates sum of all recipient amounts
    CAmount Sum() const noexcept
    {
        return std::accumulate(
            m_vec.cbegin(), m_vec.cend(), CAmount{0},
            [](CAmount sum, const CRecipient& recipient) { return sum + recipient.nAmount; });
    }

    size_t NumOutputsToSubtractFeeFrom() const noexcept
    {
        return std::count_if(cbegin(), cend(), [](const CRecipient& r) { return r.fSubtractFeeFromAmount; });
    }

    const std::vector<CRecipient>& All() const noexcept { return m_vec; }

    std::vector<CRecipient> LTC() const noexcept
    {
        std::vector<CRecipient> ltc_recipients;
        std::copy_if(cbegin(), cend(), std::back_inserter(ltc_recipients), [](const CRecipient& r) { return !r.IsMWEB(); });
        return ltc_recipients;
    }

    std::vector<CRecipient> MWEB() const noexcept
    {
        std::vector<CRecipient> mweb_recipients;
        std::copy_if(cbegin(), cend(), std::back_inserter(mweb_recipients), [](const CRecipient& r) { return r.IsMWEB(); });
        return mweb_recipients;
    }
};

} // namespace wallet
