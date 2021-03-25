#pragma once

#include <mw/crypto/Crypto.h>

class Blinds
{
public:
    Blinds() = default;

    Blinds& Add(const BlindingFactor& blind)
    {
        m_positive.push_back(blind);
        return *this;
    }

    Blinds& Add(BlindingFactor&& blind)
    {
        m_positive.push_back(std::move(blind));
        return *this;
    }

    Blinds& Add(const std::vector<BlindingFactor>& blinds)
    {
        m_positive.insert(m_positive.end(), blinds.cbegin(), blinds.cend());
        return *this;
    }

    Blinds& Sub(const BlindingFactor& blind)
    {
        m_negative.push_back(blind);
        return *this;
    }

    Blinds& Sub(BlindingFactor&& blind)
    {
        m_negative.push_back(std::move(blind));
        return *this;
    }

    Blinds& Sub(const std::vector<BlindingFactor>& blinds)
    {
        m_negative.insert(m_negative.end(), blinds.cbegin(), blinds.cend());
        return *this;
    }

    BlindingFactor Total() const { return Crypto::AddBlindingFactors(m_positive, m_negative); }

private:
    std::vector<BlindingFactor> m_positive;
    std::vector<BlindingFactor> m_negative;
};