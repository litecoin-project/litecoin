#pragma once

#include <mw/common/Macros.h>
#include <string>

MW_NAMESPACE

class ChainParams
{
public:
    static void Initialize(const std::string& hrp, const uint64_t pegin_maturity)
    {
        s_hrp = hrp;
        s_pegin_maturity = pegin_maturity;
    }

    static const std::string& GetHRP() noexcept { return s_hrp; }
    static uint64_t GetPegInMaturity() noexcept { return s_pegin_maturity; }

private:
    inline static std::string s_hrp = "tmwltc";
    inline static uint64_t s_pegin_maturity = 20;
};

END_NAMESPACE