#pragma once

#include <mw/models/tx/Input.h>
#include <mw/models/tx/Output.h>
#include <mw/models/crypto/BlindingFactor.h>
#include <mw/traits/Serializable.h>

class PartialTx : public Traits::ISerializable
{
public:
    PartialTx(
        const uint64_t amount,
        const uint64_t fee,
        const std::vector<Input>& inputs,
        const std::vector<Output>& change,
        const BlindingFactor& blind
    ) : m_amount(amount), m_fee(fee), m_inputs(inputs), m_change(change), m_blind(blind) { }

    uint64_t GetAmount() const noexcept { return m_amount; }
    uint64_t GetFee() const noexcept { return m_fee; }
    const std::vector<Input>& GetInputs() const noexcept { return m_inputs; }
    const std::vector<Output>& GetChange() const noexcept { return m_change; }
    const BlindingFactor& GetBlind() const noexcept { return m_blind; }

    Serializer& Serialize(Serializer& serializer) const noexcept
    {
        return serializer
            .Append(m_amount)
            .Append(m_fee)
            .AppendVec(m_inputs)
            .AppendVec(m_change)
            .Append(m_blind);
    }

    static PartialTx Deserialize(Deserializer& deserializer)
    {
        const uint64_t amount = deserializer.Read<uint64_t>();
        const uint64_t fee = deserializer.Read<uint64_t>();
        std::vector<Input> inputs = deserializer.ReadVec<Input>();
        std::vector<Output> change = deserializer.ReadVec<Output>();
        BlindingFactor blind = BlindingFactor::Deserialize(deserializer);

        return PartialTx(amount, fee, inputs, change, blind);
    }

private:
    // The amount being sent.
    uint64_t m_amount;

    // The total transaction fee.
    uint64_t m_fee;

    // The sender's inputs.
    std::vector<Input> m_inputs;

    // The sender's change outputs.
    std::vector<Output> m_change;

    // The difference between the change blinding factors and the input blinding factors.
    // Used by the receiver to calculate the kernel signature.
    // This is NOT secure. Used only for testnet.
    BlindingFactor m_blind;
};