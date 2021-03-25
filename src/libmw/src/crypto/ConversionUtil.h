#pragma once

#include "Context.h"

#include <mw/models/crypto/Commitment.h>
#include <mw/models/crypto/PublicKey.h>
#include <mw/models/crypto/Signature.h>

class ConversionUtil
{
public:
    ConversionUtil(const Locked<Context>& context) : m_context(context) { }

    PublicKey ToPublicKey(const Commitment& commitment) const;
    PublicKey ToPublicKey(const secp256k1_pubkey& pubkey) const;
    Commitment ToCommitment(const secp256k1_pedersen_commitment& commitment) const;
    CompactSignature ToCompact(const Signature& signature) const;
    CompactSignature ToCompact(const secp256k1_ecdsa_signature& signature) const;

    secp256k1_pubkey ToSecp256k1(const PublicKey& publicKey) const;
    std::vector<secp256k1_pubkey> ToSecp256k1(const std::vector<PublicKey>& publicKeys) const;

    secp256k1_pedersen_commitment ToSecp256k1(const Commitment& commitment) const;
    std::vector<secp256k1_pedersen_commitment> ToSecp256k1(const std::vector<Commitment>& commitments) const;

    secp256k1_ecdsa_signature ToSecp256k1(const CompactSignature& signature) const;
    std::vector<secp256k1_ecdsa_signature> ToSecp256k1(const std::vector<CompactSignature>& signatures) const;

    secp256k1_schnorrsig ToSecp256k1(const Signature& signature) const;
    std::vector<secp256k1_schnorrsig> ToSecp256k1(const std::vector<const Signature*>& signatures) const;
    Signature ToSignature(const secp256k1_schnorrsig& signature) const;

private:
    Locked<Context> m_context;
};