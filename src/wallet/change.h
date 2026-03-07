#pragma once

#include <primitives/transaction.h>
#include <script/address.h>
#include <wallet/coincontrol.h>
#include <wallet/coinselection.h>
#include <wallet/reserve.h>
#include <wallet/wallet.h>

#include <optional>

namespace wallet {

// Forward Declarations
class CRecipients;
class CWallet;

struct MWEBChangePosition
{
    // The position of the change output in the MWEB outputs vector.
    // For signed transactions this is the canonical position after MWEB output sorting.
    size_t idx;

    //! The hash will only be populated for signed transactions.
    std::optional<mw::Hash> hash;
};

struct ChangePosition
{
    std::optional<std::variant<size_t, MWEBChangePosition>> position;

    ChangePosition() = default;
    ChangePosition(const size_t i) : position(std::make_optional(i)) {}
    ChangePosition(MWEBChangePosition mweb_pos) : position(std::make_optional(std::move(mweb_pos))) {}

    bool operator==(const size_t i) const noexcept { return IsLTC() && ToLTC() == i; }
    bool operator==(const mw::Hash& id) const noexcept { return IsMWEB() && ToMWEB().hash == id; }

    void SetNull() noexcept { position = std::nullopt; }
    bool IsNull() const noexcept { return !position.has_value(); }

    bool IsLTC() const noexcept { return position.has_value() && std::holds_alternative<size_t>(*position); }
    size_t ToLTC() const noexcept
    {
        assert(IsLTC());
        return std::get<size_t>(*position);
    }
    bool IsMWEB() const noexcept { return position.has_value() && std::holds_alternative<MWEBChangePosition>(*position); }
    const MWEBChangePosition& ToMWEB() const noexcept
    {
        assert(IsMWEB());
        return std::get<MWEBChangePosition>(*position);
    }
};

struct ChangeBuilder
{
    ChangePosition change_position;
    GenericAddress script_or_address;
    std::shared_ptr<ReserveDestination> reserve_dest;
    CAmount amount;
    bilingual_str error;

    static ChangeBuilder New(const CWallet& wallet, const CCoinControl& coin_control, const CRecipients& recipients, const std::optional<int>& change_position);

    ChangeParams BuildMWEBParams(const CoinSelectionParams& coin_selection_params) const;
    ChangeParams BuildLTCParams(const CWallet& wallet, const CoinSelectionParams& coin_selection_params, const CRecipients& recipients) const;
    std::optional<ChangeParams> BuildParams(const CWallet& wallet, const CCoinControl& coin_control, const CoinSelectionParams& coin_selection_params, const CRecipients& recipients) const;

    static bool ChangeBelongsOnMWEB(const TxType& tx_type, const CTxDestination& dest_change);

    const ChangePosition& GetPosition() const noexcept { return change_position; }
};

} // namespace wallet
