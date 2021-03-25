#pragma once

#include <mw/models/crypto/Commitment.h>
#include <mw/traits/Serializable.h>
#include <mw/traits/Printable.h>

//
// Represents coins being pegged in, i.e. moved from canonical chain to the extension block.
//
class PegInCoin : public Traits::ISerializable, public Traits::IPrintable
{
public:
    PegInCoin(const uint64_t amount, const Commitment& commitment)
        : m_amount(amount), m_commitment(commitment) { }
    PegInCoin(const uint64_t amount, Commitment&& commitment)
        : m_amount(amount), m_commitment(std::move(commitment)) { }

    bool operator==(const PegInCoin& rhs) const noexcept
    {
        return m_amount == rhs.m_amount && m_commitment == rhs.m_commitment;
    }

    uint64_t GetAmount() const noexcept { return m_amount; }
    const Commitment& GetCommitment() const noexcept { return m_commitment; }

    //
    // Serialization/Deserialization
    //
    Serializer& Serialize(Serializer& serializer) const noexcept final
    {
        return serializer
            .Append(m_amount)
            .Append(m_commitment);
    }

    static PegInCoin Deserialize(Deserializer& deserializer)
    {
        uint64_t amount = deserializer.Read<uint64_t>();
        Commitment commitment = Commitment::Deserialize(deserializer);

        return PegInCoin(amount, std::move(commitment));
    }

    std::string Format() const noexcept final
    {
        return std::string("PegInCoin(commitment: ") + m_commitment.Format() + ", amount: " + std::to_string(m_amount) + ")";
    }

private:
    uint64_t m_amount;
    Commitment m_commitment;
};