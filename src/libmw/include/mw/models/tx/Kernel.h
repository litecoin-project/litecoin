#pragma once

#include <mw/common/Macros.h>
#include <mw/crypto/Crypto.h>
#include <mw/crypto/Hasher.h>
#include <mw/traits/Committed.h>
#include <mw/traits/Hashable.h>
#include <mw/traits/Serializable.h>
#include <mw/traits/Printable.h>
#include <mw/models/crypto/BlindingFactor.h>
#include <mw/models/crypto/Signature.h>
#include <mw/models/tx/PegOutCoin.h>
#include <mw/models/tx/KernelType.h>
#include <boost/optional.hpp>

class Kernel :
    public Traits::ICommitted,
    public Traits::IHashable,
    public Traits::ISerializable
{
public:
    Kernel() = default;
    Kernel(
        boost::optional<uint64_t> fee,
        boost::optional<uint64_t> pegin,
        boost::optional<PegOutCoin> pegout,
        boost::optional<uint64_t> lockHeight,
        std::vector<uint8_t> extraData,
        Commitment&& excess,
        Signature&& signature
    ) : m_fee(fee),
        m_pegin(pegin),
        m_pegout(std::move(pegout)),
        m_lockHeight(lockHeight),
        m_extraData(std::move(extraData)),
        m_excess(std::move(excess)),
        m_signature(std::move(signature))
    {
        m_hash = Hashed(*this);
    }

    //
    // Factories
    //
    static Kernel Create(
        const BlindingFactor& blind,
        const boost::optional<uint64_t>& fee,
        const boost::optional<uint64_t>& pegin_amount,
        const boost::optional<PegOutCoin>& pegout,
        const boost::optional<uint64_t>& lock_height
    );

    //
    // Operators
    //
    bool operator<(const Kernel& rhs) const { return GetHash() < rhs.GetHash(); }
    bool operator==(const Kernel& rhs) const { return GetHash() == rhs.GetHash(); }
    bool operator!=(const Kernel& rhs) const { return GetHash() != rhs.GetHash(); }

    //
    // Getters
    //
    uint64_t GetFee() const noexcept { return m_fee.value_or(0); }
    uint64_t GetLockHeight() const noexcept { return m_lockHeight.value_or(0); }
    const Commitment& GetExcess() const noexcept { return m_excess; }
    const Signature& GetSignature() const noexcept { return m_signature; }
    const std::vector<uint8_t>& GetExtraData() const noexcept { return m_extraData; }

    mw::Hash GetSignatureMessage() const;
    static mw::Hash GetSignatureMessage(
        const boost::optional<uint64_t>& fee,
        const boost::optional<uint64_t>& pegin_amount,
        const boost::optional<PegOutCoin>& pegout,
        const boost::optional<uint64_t>& lock_height,
        const std::vector<uint8_t>& extra_data
    );

    bool HasPegIn() const noexcept { return m_pegin.has_value(); }
    bool HasPegOut() const noexcept { return m_pegout.has_value(); }

    uint64_t GetPegIn() const noexcept { return m_pegin.value_or(0); }
    const boost::optional<PegOutCoin>& GetPegOut() const noexcept { return m_pegout; }

    int64_t GetSupplyChange() const noexcept
    {
        return (m_pegin.value_or(0) - m_fee.value_or(0)) -
            (int64_t)(m_pegout.has_value() ? m_pegout.value().GetAmount() : 0);
    }

    //
    // Serialization/Deserialization
    //
    Serializer& Serialize(Serializer& serializer) const noexcept final;
    static Kernel Deserialize(Deserializer& deserializer);

    //
    // Traits
    //
    mw::Hash GetHash() const noexcept final { return m_hash; }

    const Commitment& GetCommitment() const noexcept final { return m_excess; }

private:
    boost::optional<uint64_t> m_fee;
    boost::optional<uint64_t> m_pegin;
    boost::optional<PegOutCoin> m_pegout;
    boost::optional<uint64_t> m_lockHeight;
    std::vector<uint8_t> m_extraData;

    // Remainder of the sum of all transaction commitments. 
    // If the transaction is well formed, amounts components should sum to zero and the excess is hence a valid public key.
    Commitment m_excess;

    // The signature proving the excess is a valid public key, which signs the transaction fee.
    Signature m_signature;

    mw::Hash m_hash;
};

// Sorts by net supply increase [pegin - (fee + pegout)] with highest increase first, then sorts by hash.
static struct
{
    bool operator()(const Kernel& a, const Kernel& b) const
    {
        int64_t a_pegin = a.GetSupplyChange();
        int64_t b_pegin = b.GetSupplyChange();
        return (a_pegin > b_pegin) || (a_pegin == b_pegin && a.GetHash() < b.GetHash());
    }
} KernelSort;