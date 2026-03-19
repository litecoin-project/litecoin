#include <mw/models/tx/Output.h>
#include <mw/models/tx/OutputMask.h>
#include <mw/models/wallet/StealthAddress.h>
#include <mw/crypto/Bulletproofs.h>
#include <mw/crypto/Pedersen.h>
#include <mw/crypto/Schnorr.h>
#include <mw/common/Logger.h>

MW_NAMESPACE

Output Output::Create(
    BlindingFactor* blind_out,
    const SecretKey& sender_privkey,
    const StealthAddress& receiver_addr,
    const uint64_t value)
{
    // We only support standard feature fields for now
    const uint8_t features = OutputMessage::STANDARD_FIELDS_FEATURE_BIT;

    // Generate 128-bit secret nonce 'n' = Hash128(T_nonce, sender_privkey)
    BigInt<16> n(Hashed(EHashTag::NONCE, sender_privkey).data());

    // Calculate unique sending key 's' = H(T_send, Ai, Bi, v, n)
    SecretKey s = Hasher(EHashTag::SEND_KEY)
        .Append(receiver_addr.A())
        .Append(receiver_addr.B())
        .Append(value)
        .Append(n)
        .hash();

    // Derive shared secret 'e' = H(T_derive, s*Ai)
    PublicKey sA = receiver_addr.A().Mul(s);
    SecretKey e = Hashed(EHashTag::DERIVE, sA);

    // Construct one-time public key for receiver 'Ko' = H(T_outkey, e)*Bi
    PublicKey Ko = receiver_addr.B().Mul(Hashed(EHashTag::OUT_KEY, e));

    // Key exchange public key 'Ke' = s*Bi
    PublicKey Ke = receiver_addr.B().Mul(s);

    // Calc blinding factor and mask nonce and amount.
    OutputMask mask = OutputMask::FromShared(e);
    BlindingFactor blind = mask.BlindSwitch(value);
    uint64_t mv = mask.MaskValue(value);
    BigInt<16> mn = mask.MaskNonce(n);

    // Commitment 'C' = r*G + v*H
    Commitment output_commit = Commitment::Blinded(blind, value);

    // Calculate the ephemeral send pubkey 'Ks' = ks*G
    PublicKey Ks = Keys::From(sender_privkey).PubKey();

    // Derive view tag as first byte of H(T_tag, sA)
    uint8_t view_tag = Hashed(EHashTag::TAG, sA)[0];

    OutputMessage message{features, OutputStandardFields(Ke, view_tag, mv, mn)};

    // MW: TODO - Need to store:
    // * Shared message = kernel_id where nonce is H(tag || shared_secret)
    // * Private message = keychain idx of sender_key + sender_key nonce + checksum where nonce is H(tag || seed-derived key || output commitment)
    RangeProof::CPtr pRangeProof = Bulletproofs::Generate(
        value,
        SecretKey(blind.vec()),
        SecretKey::Random(),
        SecretKey::Random(),
        BigInt<32>{},
        blind.GetBigInt(),
        message.Serialized()
    );
    
    // Sign the output
    mw::Hash sig_message = Hasher()
        .Append(output_commit)
        .Append(Ks)
        .Append(Ko)
        .Append(message.GetHash())
        .Append(pRangeProof->GetHash())
        .hash();
    Signature signature = Schnorr::Sign(sender_privkey.data(), sig_message);

    if (blind_out != nullptr) {
        *blind_out = mask.GetRawBlind();
    }

    return Output{
        std::move(output_commit),
        std::move(Ks),
        std::move(Ko),
        std::move(message),
        pRangeProof,
        std::move(signature)
    };
}

SignedMessage Output::BuildSignedMsg() const noexcept
{
    mw::Hash hashed_msg = Hasher()
        .Append(m_commitment)
        .Append(m_senderPubKey)
        .Append(m_receiverPubKey)
        .Append(m_message.GetHash())
        .Append(m_pProof->GetHash())
        .hash();
    return SignedMessage{ std::move(hashed_msg), m_senderPubKey, m_signature };
}

ProofData Output::BuildProofData() const noexcept
{
    return ProofData{ m_commitment, m_pProof, m_message.Serialized() };
}

END_NAMESPACE
