#include <mw/models/tx/Output.h>
#include <mw/models/tx/OutputMask.h>
#include <mw/models/wallet/StealthAddress.h>
#include <mw/crypto/Bulletproofs.h>
#include <mw/crypto/Hasher.h>
#include <mw/crypto/KeyDerivation.h>
#include <mw/crypto/Pedersen.h>
#include <mw/crypto/Schnorr.h>

MW_NAMESPACE

Output Output::Create(
    BlindingFactor* blind_out,
    const SecretKey& sender_privkey,
    const SecretKey& rewind_key,
    const StealthAddress& receiver_addr,
    const uint64_t value,
    const std::vector<uint8_t>& extra_data)
{
    const uint8_t features = static_cast<uint8_t>(
        OutputMessage::STANDARD_FIELDS_FEATURE_BIT |
        (extra_data.empty() ? 0 : OutputMessage::EXTRA_DATA_FEATURE_BIT));

    // Generate 128-bit secret nonce 'n' = Hash128(T_nonce, sender_privkey)
    BigInt<16> n = DeriveOutputNonce(sender_privkey);

    // Calculate unique sending key 's' = H(T_send, Ai, Bi, v, n)
    SecretKey s = DeriveOutputSendKey(receiver_addr, value, n);

    // Derive shared secret 'e' = H(T_derive, s*Ai)
    PublicKey sA = receiver_addr.A().Mul(s);
    SecretKey e = SecretKey::FromHash(Hashed(EHashTag::DERIVE, sA));

    // Construct one-time public key for receiver 'Ko' = H(T_outkey, e)*Bi
    PublicKey Ko = DeriveOutputPubKey(receiver_addr, e);

    // Key exchange public key 'Ke' = s*Bi
    PublicKey Ke = DeriveOutputKeyExchangePubKey(receiver_addr, s);

    // Calc blinding factor and mask nonce and amount.
    OutputMask mask = OutputMask::FromShared(e);
    BlindingFactor blind = mask.BlindSwitch(value);
    uint64_t mv = mask.MaskValue(value);
    BigInt<16> mn = mask.MaskNonce(n);

    // Commitment 'C' = r*G + v*H
    Commitment output_commit = Commitment::Blinded(blind, value);

    // Calculate the ephemeral send pubkey 'Ks' = ks*G
    PublicKey Ks = PublicKey::From(sender_privkey);

    // Derive view tag as first byte of H(T_tag, sA)
    uint8_t view_tag = Hashed(EHashTag::TAG, sA)[0];

    OutputMessage message{features, OutputStandardFields(Ke, view_tag, mv, mn), extra_data};

    SecretKey proof_nonce = SecretKey::FromHash(Hasher(EHashTag::PROOF_NONCE)
        .Append(rewind_key)
        .Append(output_commit)
        .hash());
    RangeProof::CPtr pRangeProof = Bulletproofs::Generate(
        value,
        blind,
        proof_nonce,
        e.GetBigInt(),
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
