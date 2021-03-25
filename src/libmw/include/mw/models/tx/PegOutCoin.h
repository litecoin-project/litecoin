#pragma once

#include <mw/traits/Serializable.h>
#include <mw/traits/Printable.h>

//
// Represents coins being pegged in, i.e. moved from canonical chain to the extension block.
//
class PegOutCoin : public Traits::ISerializable, public Traits::IPrintable
{
public:
    PegOutCoin(const uint64_t amount, const std::vector<uint8_t>& scriptPubKey)
        : m_amount(amount), m_scriptPubKey(scriptPubKey) { }
    PegOutCoin(const uint64_t amount, std::vector<uint8_t>&& scriptPubKey)
        : m_amount(amount), m_scriptPubKey(std::move(scriptPubKey)) { }

    bool operator==(const PegOutCoin& rhs) const noexcept
    {
        return m_amount == rhs.m_amount && m_scriptPubKey == rhs.m_scriptPubKey;
    }

    uint64_t GetAmount() const noexcept { return m_amount; }
    const std::vector<uint8_t>& GetScriptPubKey() const noexcept { return m_scriptPubKey; }

    //
    // Serialization/Deserialization
    //
    Serializer& Serialize(Serializer& serializer) const noexcept final
    {
        return serializer
            .Append(m_amount)
            .Append<uint8_t>((uint8_t)m_scriptPubKey.size())
            .Append(m_scriptPubKey);
    }

    static PegOutCoin Deserialize(Deserializer& deserializer)
    {
        uint64_t amount = deserializer.Read<uint64_t>();
        uint8_t num_bytes = deserializer.Read<uint8_t>();
        std::vector<uint8_t> scriptPubKey = deserializer.ReadVector(num_bytes);

        return PegOutCoin(amount, std::move(scriptPubKey));
    }

    std::string Format() const noexcept final
    {
        return StringUtil::Format("PegOutCoin(pubkey:{}, amount:{})", HexUtil::ToHex(m_scriptPubKey), m_amount);
    }

private:
    uint64_t m_amount;
    std::vector<uint8_t> m_scriptPubKey;
};