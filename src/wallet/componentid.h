#pragma once

#include <primitives/transaction.h>

namespace wallet {

struct PegoutIndex {
    // The ID of the kernel containing the pegout.
    mw::Hash kernel_id;

    // The position of the PegOutCoin within the kernel.
    // Ex: If a kernel has 3 pegouts, the last one will have a pos of 2.
    size_t pos;

    bool operator==(const PegoutIndex& pegout_idx) const noexcept { return pegout_idx.kernel_id == kernel_id && pegout_idx.pos == pos; }

    std::string ToString() const noexcept { return strprintf("%s:%u", kernel_id.ToHex(), pos); }
};

class GenericComponentID
{
    std::variant<COutPoint, mw::Hash, PegoutIndex> m_value;

public:
    GenericComponentID() = default;
    GenericComponentID(COutPoint outpoint) : m_value(std::move(outpoint)) {}
    GenericComponentID(mw::Hash hash) : m_value(std::move(hash)) {}
    GenericComponentID(PegoutIndex pegout_idx) : m_value(std::move(pegout_idx)) {}
    GenericComponentID(const AnyOutputID& output_id)
    {
        if (output_id.IsMWEB()) {
            m_value = output_id.ToMWEB();
        } else {
            m_value = output_id.ToOutPoint();
        }
    }

    bool operator==(const GenericComponentID& id) const noexcept { return id.m_value == m_value; }
    bool operator==(const COutPoint& outpoint) const noexcept { return IsOutPoint() && ToOutPoint() == outpoint; }
    bool operator==(const mw::Hash& mweb_hash) const noexcept { return IsMWEBOutputID() && ToMWEBOutputID() == mweb_hash; }
    bool operator==(const PegoutIndex& pegout_idx) const noexcept { return IsPegoutIndex() && ToPegoutIndex() == pegout_idx; }

    bool IsOutPoint() const noexcept { return std::holds_alternative<COutPoint>(m_value); }
    bool IsMWEBOutputID() const noexcept { return std::holds_alternative<mw::Hash>(m_value); }
    bool IsPegoutIndex() const noexcept { return std::holds_alternative<PegoutIndex>(m_value); }

    const mw::Hash& ToMWEBOutputID() const noexcept
    {
        assert(IsMWEBOutputID());
        return std::get<mw::Hash>(m_value);
    }

    const COutPoint& ToOutPoint() const noexcept
    {
        assert(IsOutPoint());
        return std::get<COutPoint>(m_value);
    }

    const PegoutIndex& ToPegoutIndex() const noexcept
    {
        assert(IsPegoutIndex());
        return std::get<PegoutIndex>(m_value);
    }

    std::string ToString() const noexcept
    {
        if (IsOutPoint()) {
            return std::to_string(ToOutPoint().n);
        } else if (IsMWEBOutputID()) {
            return "MWEB Output (" + ToMWEBOutputID().ToHex() + ")";
        } else {
            const PegoutIndex& pegout_idx = ToPegoutIndex();
            return "Pegout (" + pegout_idx.kernel_id.ToHex() + ":" + std::to_string(pegout_idx.pos) + ")";
        }
    }
};
}
