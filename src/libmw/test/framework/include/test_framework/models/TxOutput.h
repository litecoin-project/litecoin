#pragma once

#include <mw/common/Macros.h>
#include <mw/models/tx/Output.h>
#include <mw/models/wallet/StealthAddress.h>
#include <mw/crypto/Bulletproofs.h>
#include <mw/crypto/Hasher.h>
#include <mw/crypto/Pedersen.h>
#include <mw/crypto/SecretKeys.h>

TEST_NAMESPACE

class TxOutput
{
public:
    TxOutput(BlindingFactor&& blindingFactor, const uint64_t amount, Output&& output, SecretKey spend_key = {})
        : m_blindingFactor(std::move(blindingFactor)),
          m_amount(amount),
          m_output(std::move(output)),
          m_spendKey(std::move(spend_key)) { }

    static TxOutput Create(
        const SecretKey& sender_privkey,
        const StealthAddress& receiver_addr,
        const uint64_t amount)
    {
        BlindingFactor raw_blind;
        Output output = Output::Create(&raw_blind, sender_privkey, receiver_addr, amount);
        BlindingFactor blind_switch = Pedersen::BlindSwitch(raw_blind, amount);

        return TxOutput{std::move(blind_switch), amount, std::move(output)};
    }
    
    static TxOutput Create(
        const SecretKey& sender_privkey,
        const SecretKey& receiver_scan_key,
        const SecretKey& receiver_spend_key,
        const uint64_t amount)
    {
        StealthAddress receiver_addr(
            PublicKey::From(receiver_spend_key).Mul(receiver_scan_key),
            PublicKey::From(receiver_spend_key)
        );
        BlindingFactor raw_blind;
        Output output = Output::Create(&raw_blind, sender_privkey, receiver_addr, amount);
        BlindingFactor blind_switch = Pedersen::BlindSwitch(raw_blind, amount);
        SecretKey t = SecretKey::FromHash(Hashed(EHashTag::DERIVE, output.Ke().Mul(receiver_scan_key)));
        SecretKey output_key = SecretKeys::From(receiver_spend_key)
            .Mul(SecretKey::FromHash(Hashed(EHashTag::OUT_KEY, t)))
            .Total();

        return TxOutput{std::move(blind_switch), amount, std::move(output), output_key};
    }


    const BlindingFactor& GetBlind() const noexcept { return m_blindingFactor; }
    const SecretKey& GetSpendKey() const noexcept { return m_spendKey; }
    uint64_t GetAmount() const noexcept { return m_amount; }
    const Output& GetOutput() const noexcept { return m_output; }
    const Commitment& GetCommitment() const noexcept { return m_output.GetCommitment(); }
    const mw::Hash& GetOutputID() const noexcept { return m_output.GetOutputID(); }

private:
    BlindingFactor m_blindingFactor;
    uint64_t m_amount;
    Output m_output;
    SecretKey m_spendKey;
};

END_NAMESPACE