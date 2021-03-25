#pragma once

// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <mw/models/tx/Features.h>
#include <mw/models/tx/OutputId.h>
#include <mw/models/crypto/BlindingFactor.h>
#include <mw/models/crypto/Commitment.h>
#include <mw/models/crypto/ProofData.h>
#include <mw/models/crypto/RangeProof.h>
#include <mw/models/crypto/SecretKey.h>
#include <mw/models/crypto/SignedMessage.h>
#include <mw/traits/Committed.h>
#include <mw/traits/Serializable.h>

// Forward Declarations
class StealthAddress;

////////////////////////////////////////
// OUTPUT
////////////////////////////////////////
class Output :
    public Traits::ICommitted,
    public Traits::ISerializable
{
public:
    //
    // Constructors
    //
    Output(
        Commitment&& commitment,
        Features features,
        PublicKey&& receiver_pubkey,
        PublicKey&& key_exchange_pubkey,
        uint8_t view_tag,
        uint64_t masked_value,
        BigInt<16>&& masked_nonce,
        PublicKey&& sender_pubkey,
        Signature&& signature,
        const RangeProof::CPtr& pProof
    );
    Output(const Output& Output) = default;
    Output(Output&& Output) noexcept = default;
    Output() = default;

    //
    // Factory
    //
    static Output Create(
        BlindingFactor& blind_out,
        const Features& features,
        const SecretKey& sender_privkey,
        const StealthAddress& receiver_addr,
        const uint64_t value
    );

    //
    // Destructor
    //
    virtual ~Output() = default;

    //
    // Operators
    //
    Output& operator=(const Output& Output) = default;
    Output& operator=(Output&& Output) noexcept = default;
    bool operator<(const Output& Output) const noexcept { return m_hash < Output.m_hash; }
    bool operator==(const Output& Output) const noexcept { return m_hash == Output.m_hash; }

    //
    // Getters
    //
    const Commitment& GetCommitment() const noexcept final { return m_commitment; }
    const RangeProof::CPtr& GetRangeProof() const noexcept { return m_pProof; }

    Features GetFeatures() const noexcept { return m_features; }
    const PublicKey& GetReceiverPubKey() const noexcept { return m_receiverPubKey; }
    const PublicKey& GetKeyExchangePubKey() const noexcept { return m_keyExchangePubKey; }
    uint8_t GetViewTag() const noexcept { return m_viewTag; }
    uint64_t GetMaskedValue() const noexcept { return m_maskedValue; }
    const BigInt<16>& GetMaskedNonce() const noexcept { return m_maskedNonce; }
    const PublicKey& GetSenderPubKey() const noexcept { return m_senderPubKey; }
    const Signature& GetSignature() const noexcept { return m_signature; }

    const PublicKey& Ko() const noexcept { return m_receiverPubKey; }
    const PublicKey& Ke() const noexcept { return m_keyExchangePubKey; }

    SignedMessage BuildSignedMsg() const noexcept;
    ProofData BuildProofData() const noexcept;

    bool IsPeggedIn() const noexcept { return GetFeatures().IsSet(EOutputFeatures::PEGGED_IN); }

    OutputId ToOutputId() const noexcept {
        return OutputId(
            m_commitment,
            m_features,
            m_receiverPubKey,
            m_keyExchangePubKey,
            m_viewTag,
            m_maskedValue,
            m_maskedNonce,
            m_senderPubKey
        );
    }

    //
    // Serialization/Deserialization
    //
    Serializer& Serialize(Serializer& serializer) const noexcept final;
    static Output Deserialize(Deserializer& deserializer);

private:
    // The homomorphic commitment representing the output amount
    Commitment m_commitment;

    Features m_features;
    PublicKey m_receiverPubKey;
    PublicKey m_keyExchangePubKey;
    uint8_t m_viewTag;
    uint64_t m_maskedValue;
    BigInt<16> m_maskedNonce;
    PublicKey m_senderPubKey;
    Signature m_signature;

    // A proof that the commitment is in the right range
    RangeProof::CPtr m_pProof;

    mw::Hash m_hash;
};