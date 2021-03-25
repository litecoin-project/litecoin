#include "ConversionUtil.h"

#include <mw/exceptions/CryptoException.h>

PublicKey ConversionUtil::ToPublicKey(const Commitment& commitment) const
{
    secp256k1_pedersen_commitment parsedCommitment = ToSecp256k1(commitment);

    secp256k1_pubkey pubkey;
    const int pubkeyResult = secp256k1_pedersen_commitment_to_pubkey(
        m_context.Read()->Get(),
        &pubkey,
        &parsedCommitment
    );

    if (pubkeyResult != 1)
    {
        ThrowCrypto_F("Failed to convert commitment ({}) to pubkey", commitment);
    }

    return ToPublicKey(pubkey);
}

PublicKey ConversionUtil::ToPublicKey(const secp256k1_pubkey& pubkey) const
{
    PublicKey result;
    size_t length = result.size();
    const int serializeResult = secp256k1_ec_pubkey_serialize(
        m_context.Read()->Get(),
        result.data(),
        &length,
        &pubkey,
        SECP256K1_EC_COMPRESSED
    );
    if (serializeResult != 1)
    {
        ThrowCrypto("Failed to convert to PublicKey");
    }

    return result;
}

secp256k1_pubkey ConversionUtil::ToSecp256k1(const PublicKey& publicKey) const
{
    secp256k1_pubkey parsedPubkey;
    const int pubkeyResult = secp256k1_ec_pubkey_parse(
        m_context.Read()->Get(),
        &parsedPubkey,
        publicKey.data(),
        publicKey.size()
    );
    if (pubkeyResult != 1)
    {
        ThrowCrypto_F("Failed to parse pubkey: {}", publicKey);
    }

    return parsedPubkey;
}

std::vector<secp256k1_pubkey> ConversionUtil::ToSecp256k1(const std::vector<PublicKey>& publicKeys) const
{
    std::vector<secp256k1_pubkey> out;
    out.reserve(publicKeys.size());
    std::transform(
        publicKeys.cbegin(), publicKeys.cend(),
        std::back_inserter(out),
        [this](const PublicKey& publicKey) { return ToSecp256k1(publicKey); }
    );

    return out;
}

secp256k1_pedersen_commitment ConversionUtil::ToSecp256k1(const Commitment& commitment) const
{
    secp256k1_pedersen_commitment parsedCommitment;
    const int commitmentResult = secp256k1_pedersen_commitment_parse(
        m_context.Read()->Get(),
        &parsedCommitment,
        commitment.data()
    );
    if (commitmentResult != 1)
    {
        ThrowCrypto_F("Failed to parse commitment: {}", commitment);
    }

    return parsedCommitment;
}

Commitment ConversionUtil::ToCommitment(const secp256k1_pedersen_commitment& commitment) const
{
    Commitment out;
    const int serializedResult = secp256k1_pedersen_commitment_serialize(
        m_context.Read()->Get(),
        out.data(),
        &commitment
    );
    if (serializedResult != 1)
    {
        ThrowCrypto("Failed to serialize commitment.");
    }

    return out;
}

std::vector<secp256k1_pedersen_commitment> ConversionUtil::ToSecp256k1(const std::vector<Commitment>& commitments) const
{
    std::vector<secp256k1_pedersen_commitment> out;
    out.reserve(commitments.size());
    std::transform(
        commitments.cbegin(), commitments.cend(),
        std::back_inserter(out),
        [this](const Commitment& commit) { return ToSecp256k1(commit); }
    );

    return out;
}

secp256k1_ecdsa_signature ConversionUtil::ToSecp256k1(const CompactSignature& signature) const
{
    secp256k1_ecdsa_signature secpSig;
    const int parseSignatureResult = secp256k1_ecdsa_signature_parse_compact(
        m_context.Read()->Get(),
        &secpSig,
        signature.data()
    );
    if (parseSignatureResult != 1)
    {
        ThrowCrypto_F("Failed to parse signature: {}", signature);
    }

    return secpSig;
}

std::vector<secp256k1_ecdsa_signature> ConversionUtil::ToSecp256k1(const std::vector<CompactSignature>& signatures) const
{
    std::vector<secp256k1_ecdsa_signature> out;
    out.reserve(signatures.size());
    std::transform(
        signatures.cbegin(), signatures.cend(),
        std::back_inserter(out),
        [this](const CompactSignature& signature) { return ToSecp256k1(signature); }
    );

    return out;
}

secp256k1_schnorrsig ConversionUtil::ToSecp256k1(const Signature& signature) const
{
    secp256k1_schnorrsig secpSig;
    const int parseSignatureResult = secp256k1_schnorrsig_parse(
        m_context.Read()->Get(),
        &secpSig,
        signature.data()
    );
    if (parseSignatureResult != 1)
    {
        ThrowCrypto_F("Failed to parse signature: {}", signature);
    }

    return secpSig;
}

std::vector<secp256k1_schnorrsig> ConversionUtil::ToSecp256k1(const std::vector<const Signature*>& signatures) const
{
    std::vector<secp256k1_schnorrsig> out;
    out.reserve(signatures.size());
    std::transform(
        signatures.cbegin(), signatures.cend(),
        std::back_inserter(out),
        [this](const Signature* pSignature) { return ToSecp256k1(*pSignature); }
    );

    return out;
}

CompactSignature ConversionUtil::ToCompact(const Signature& signature) const
{
    secp256k1_ecdsa_signature sig;
    memcpy(sig.data, signature.data(), sizeof(sig.data));
    return ToCompact(sig);
}

CompactSignature ConversionUtil::ToCompact(const secp256k1_ecdsa_signature& signature) const
{
    CompactSignature sig64;
    const int serializedResult = secp256k1_ecdsa_signature_serialize_compact(
        m_context.Read()->Get(),
        sig64.data(),
        &signature
    );
    if (serializedResult != 1)
    {
        ThrowCrypto("Failed to serialize signature.");
    }

    return sig64;
}

Signature ConversionUtil::ToSignature(const secp256k1_schnorrsig& signature) const
{
    Signature out;
    const int serializedResult = secp256k1_schnorrsig_serialize(m_context.Read()->Get(), out.data(), &signature);
    if (serializedResult != 1)
    {
        ThrowCrypto("Failed to serialize signature.");
    }

    return out;
}