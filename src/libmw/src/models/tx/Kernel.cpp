#include <mw/models/tx/Kernel.h>
#include <mw/crypto/Schnorr.h>
#include <mw/crypto/SecretKeys.h>

MW_NAMESPACE

Kernel Kernel::Create(
    const BlindingFactor& blind,
    const std::optional<SecretKey>& stealth_blind,
    const std::optional<CAmount>& fee,
    const std::optional<CAmount>& pegin_amount,
    const std::vector<PegOutCoin>& pegouts,
    const std::optional<int32_t>& lock_height,
    const std::vector<uint8_t>& extra_data)
{
    const uint8_t features_byte = static_cast<uint8_t>(
        (fee ? FEE_FEATURE_BIT : 0) |
        (pegin_amount ? PEGIN_FEATURE_BIT : 0) |
        (pegouts.empty() ? 0 : PEGOUT_FEATURE_BIT) |
        (lock_height ? HEIGHT_LOCK_FEATURE_BIT : 0) |
        (stealth_blind ? STEALTH_EXCESS_FEATURE_BIT : 0) |
        (extra_data.empty() ? 0 : EXTRA_DATA_FEATURE_BIT));

    SecretKey sig_key(blind.data());
    Commitment excess_commit = Commitment::Blinded(blind, 0);
    std::optional<PublicKey> stealth_excess = std::nullopt;

    if (stealth_blind) {
        stealth_excess = PublicKey::From(stealth_blind.value());

        Hasher h;
        h << PublicKey::From(excess_commit) << stealth_excess.value();

        sig_key = SecretKeys::From(sig_key)
            .Mul(SecretKey::FromHash(h.hash()))
            .Add(stealth_blind.value())
            .Total();
    }

    mw::Hash sig_message = Kernel::GetSignatureMessage(
        features_byte,
        excess_commit,
        stealth_excess,
        fee,
        pegin_amount,
        pegouts,
        lock_height,
        extra_data
    );
    Signature sig = Schnorr::Sign(sig_key.data(), sig_message);
    return Kernel(
        features_byte,
        fee,
        pegin_amount,
        pegouts,
        lock_height,
        std::move(stealth_excess),
        extra_data,
        std::move(excess_commit),
        std::move(sig)
    );
}

SignedMessage Kernel::BuildSignedMsg() const
{
    PublicKey public_key = PublicKey::From(GetExcess());
    if (HasStealthExcess()) {
        PublicKey stealth_excess = GetStealthExcess();

        Hasher h;
        h << public_key << stealth_excess;

        public_key = public_key
            .Mul(SecretKey::FromHash(h.hash()))
            .Add(stealth_excess);
    }

    mw::Hash sig_message = Kernel::GetSignatureMessage(
        m_features,
        m_excess,
        m_stealthExcess,
        m_fee,
        m_pegin,
        m_pegouts,
        m_lockHeight,
        m_extraData
    );
    return SignedMessage{sig_message, public_key, GetSignature()};
}

mw::Hash Kernel::GetSignatureMessage(
    const uint8_t features,
    const Commitment& excess_commitment,
    const std::optional<PublicKey>& stealth_commitment,
    const std::optional<CAmount>& fee,
    const std::optional<CAmount>& pegin_amount,
    const std::vector<PegOutCoin>& pegouts,
    const std::optional<int32_t>& lock_height,
    const std::vector<uint8_t>& extra_data)
{
    Hasher s;
    s << features << excess_commitment;

    if (fee) {
        ::WriteVarInt<Hasher, VarIntMode::NONNEGATIVE_SIGNED, CAmount>(s, fee.value());
    }

    if (pegin_amount) {
        ::WriteVarInt<Hasher, VarIntMode::NONNEGATIVE_SIGNED, CAmount>(s, pegin_amount.value());
    }

    if (!pegouts.empty()) {
        s << pegouts;
    }

    if (lock_height) {
        ::WriteVarInt<Hasher, VarIntMode::NONNEGATIVE_SIGNED, int32_t>(s, lock_height.value());
    }

    if (stealth_commitment) {
        s << stealth_commitment.value();
    }

    if (!extra_data.empty()) {
        s << extra_data;
    }

    return s.hash();
}

END_NAMESPACE
