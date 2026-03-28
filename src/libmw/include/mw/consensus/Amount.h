#pragma once

#include <amount.h>
#include <mw/exceptions/ValidationException.h>

#include <boost/optional.hpp>
#include <limits>

namespace AmountUtil
{
inline bool IsValidMoney(const CAmount amount) noexcept
{
    return MoneyRange(amount);
}

inline bool IsValidAmountRange(const CAmount amount) noexcept
{
    return amount >= -MAX_MONEY && amount <= MAX_MONEY;
}

inline void ValidateMoney(const CAmount amount)
{
    if (!IsValidMoney(amount)) {
        ThrowValidation(EConsensusError::AMOUNT_OUT_OF_RANGE);
    }
}

inline void ValidateAmountRange(const CAmount amount)
{
    if (!IsValidAmountRange(amount)) {
        ThrowValidation(EConsensusError::AMOUNT_OUT_OF_RANGE);
    }
}

inline boost::optional<CAmount> TrySafeAdd(const CAmount lhs, const CAmount rhs) noexcept
{
    if ((rhs > 0 && lhs > std::numeric_limits<CAmount>::max() - rhs)
        || (rhs < 0 && lhs < std::numeric_limits<CAmount>::min() - rhs))
    {
        return boost::none;
    }

    return lhs + rhs;
}

inline CAmount SafeAdd(const CAmount lhs, const CAmount rhs)
{
    const auto sum = TrySafeAdd(lhs, rhs);
    if (!sum) {
        ThrowValidation(EConsensusError::AMOUNT_OUT_OF_RANGE);
    }

    return *sum;
}

inline boost::optional<CAmount> TrySafeSubtract(const CAmount lhs, const CAmount rhs) noexcept
{
    if ((rhs > 0 && lhs < std::numeric_limits<CAmount>::min() + rhs)
        || (rhs < 0 && lhs > std::numeric_limits<CAmount>::max() + rhs))
    {
        return boost::none;
    }

    return lhs - rhs;
}

inline CAmount SafeSubtract(const CAmount lhs, const CAmount rhs)
{
    const auto difference = TrySafeSubtract(lhs, rhs);
    if (!difference) {
        ThrowValidation(EConsensusError::AMOUNT_OUT_OF_RANGE);
    }

    return *difference;
}

inline uint64_t UnsignedAbs(const CAmount amount)
{
    return amount >= 0 ? static_cast<uint64_t>(amount) : static_cast<uint64_t>(-(amount + 1)) + 1;
}
} // namespace AmountUtil
