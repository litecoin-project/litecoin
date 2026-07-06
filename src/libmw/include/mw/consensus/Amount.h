#pragma once

#include <consensus/amount.h>

#include <limits>
#include <optional>

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

inline std::optional<CAmount> TrySafeAdd(const CAmount lhs, const CAmount rhs) noexcept
{
    if ((rhs > 0 && lhs > std::numeric_limits<CAmount>::max() - rhs)
        || (rhs < 0 && lhs < std::numeric_limits<CAmount>::min() - rhs)) {
        return std::nullopt;
    }

    return lhs + rhs;
}

inline std::optional<CAmount> TrySafeSubtract(const CAmount lhs, const CAmount rhs) noexcept
{
    if ((rhs > 0 && lhs < std::numeric_limits<CAmount>::min() + rhs)
        || (rhs < 0 && lhs > std::numeric_limits<CAmount>::max() + rhs)) {
        return std::nullopt;
    }

    return lhs - rhs;
}

inline uint64_t UnsignedAbs(const CAmount amount)
{
    return amount >= 0 ? static_cast<uint64_t>(amount) : static_cast<uint64_t>(-(amount + 1)) + 1;
}
} // namespace AmountUtil
