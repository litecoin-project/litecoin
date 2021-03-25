#pragma once

#include <mw/common/Macros.h>
#include <mw/models/tx/Input.h>
#include <mw/crypto/Schnorr.h>

TEST_NAMESPACE

class TxInput
{
public:
    TxInput(const BlindingFactor& blindingFactor, const SecretKey& sender_privkey, const uint64_t amount, const Input& input)
        : m_blindingFactor(blindingFactor), m_privkey(sender_privkey), m_amount(amount), m_input(input) { }

    static TxInput Create(
        const BlindingFactor& blindingFactor,
        const SecretKey& sender_privkey,
        const uint64_t amount)
    {
        Commitment commitment = Crypto::CommitBlinded(
            amount,
            blindingFactor
        );
        Signature sig = Schnorr::Sign(
            sender_privkey.data(),
            InputMessage()
        );

        return TxInput(
            blindingFactor,
            sender_privkey,
            amount,
            Input{
                std::move(commitment),
                Crypto::CalculatePublicKey(sender_privkey.GetBigInt()),
                std::move(sig)
            }
        );
    }

    const BlindingFactor& GetBlindingFactor() const noexcept { return m_blindingFactor; }
    const SecretKey& GetSenderKey() const noexcept { return m_privkey; }
    uint64_t GetAmount() const noexcept { return m_amount; }
    const Input& GetInput() const noexcept { return m_input; }

private:
    BlindingFactor m_blindingFactor;
    SecretKey m_privkey;
    uint64_t m_amount;
    Input m_input;
};

END_NAMESPACE