#pragma once

#include <mw/crypto/Hasher.h>
#include <mw/crypto/KeyDerivation.h>
#include <mw/crypto/Pedersen.h>
#include <mw/models/crypto/BlindingFactor.h>
#include <mw/models/crypto/SecretKey.h>
#include <crypto/common.h>

class OutputMask
{
public:
    OutputMask(const OutputMask&) = default;
    OutputMask(OutputMask&&) noexcept = default;

    //
    // Feeds the shared secret 'e' into tagged hash functions to derive:
    //  q - the blinding factor
    //  v' - the value mask
    //  n' - the nonce mask
    //
    static OutputMask FromShared(const SecretKey& shared_secret)
    {
        OutputMask mask;
        mask.pre_blind = mw::DeriveOutputRawBlind(shared_secret);
        const mw::Hash value_mask_hash = Hashed(EHashTag::VALUE_MASK, shared_secret);
        mask.value_mask = ReadLE64(value_mask_hash.data());
        mask.nonce_mask = BigInt<16>(Hashed(EHashTag::NONCE_MASK, shared_secret).data());
        return mask;
    }

    const BlindingFactor& GetRawBlind() const noexcept { return pre_blind; }
    BlindingFactor BlindSwitch(const uint64_t value) const { return Pedersen::BlindSwitch(pre_blind, value); }
    Commitment SwitchCommit(const uint64_t value) const { return Commitment::Switch(pre_blind, value); }
    BigInt<16> MaskNonce(const BigInt<16>& nonce) const { return nonce ^ nonce_mask; }
    uint64_t MaskValue(const uint64_t value) const { return value ^ value_mask; }

private:
    OutputMask() = default;

    BlindingFactor pre_blind;
    uint64_t value_mask;
    BigInt<16> nonce_mask;
};
