#pragma once

// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <mw/common/Traits.h>
#include <mw/models/crypto/BlindingFactor.h>
#include <mw/models/crypto/Commitment.h>
#include <mw/models/crypto/ProofData.h>
#include <mw/models/crypto/RangeProof.h>
#include <mw/models/crypto/SecretKey.h>
#include <mw/models/crypto/SignedMessage.h>
#include <univalue.h>

// Forward Declarations
class StealthAddress;

MW_NAMESPACE

class OutputStandardFields : public Traits::ISerializable
{
public:
    OutputStandardFields(PublicKey keyExchangePubKey, uint8_t viewTag, uint64_t maskedValue, BigInt<16> maskedNonce) :
        key_exchange_pubkey(std::move(keyExchangePubKey)), view_tag(viewTag), masked_value(maskedValue), masked_nonce(std::move(maskedNonce)) { }
    OutputStandardFields() = default;
    OutputStandardFields(const OutputStandardFields& standard_fields) = default;
    OutputStandardFields(OutputStandardFields&& standard_fields) noexcept = default;

    //
    // Operators
    //
    OutputStandardFields& operator=(const OutputStandardFields& standard_fields) = default;
    OutputStandardFields& operator=(OutputStandardFields&& standard_fields) noexcept = default;

    PublicKey key_exchange_pubkey;
    uint8_t view_tag;
    uint64_t masked_value;
    BigInt<16> masked_nonce;

    IMPL_SERIALIZABLE(OutputStandardFields, obj)
    {
        READWRITE(obj.key_exchange_pubkey);
        READWRITE(obj.view_tag);
        READWRITE(obj.masked_value);
        READWRITE(obj.masked_nonce);
    }
};

////////////////////////////////////////
// OUTPUT MESSAGE
////////////////////////////////////////
class OutputMessage : public Traits::ISerializable, public Traits::IHashable
{
public:
    //
    // Constructors
    //
    OutputMessage(uint8_t features_, OutputStandardFields standardFields_) : 
        features(features_), standard_fields(std::move(standardFields_))
    {
        m_hash = Hashed(*this);
    }
    OutputMessage(uint8_t features, std::optional<OutputStandardFields> standardFields, std::vector<uint8_t> extraData) :
        features(features), standard_fields(std::move(standardFields)),  extra_data(std::move(extraData))
    {
        m_hash = Hashed(*this);
    }
    OutputMessage(const OutputMessage& output_message) = default;
    OutputMessage(OutputMessage&& output_message) noexcept = default;
    OutputMessage() = default;

    enum FeatureBit {
        STANDARD_FIELDS_FEATURE_BIT = 0x01,
        EXTRA_DATA_FEATURE_BIT = 0x02
    };

    //
    // Operators
    //
    OutputMessage& operator=(const OutputMessage& output_message) = default;
    OutputMessage& operator=(OutputMessage&& output_message) noexcept = default;
    bool operator<(const OutputMessage& output_message) const noexcept { return m_hash < output_message.m_hash; }
    bool operator==(const OutputMessage& output_message) const noexcept { return m_hash == output_message.m_hash; }

    uint8_t features{0};
    std::optional<OutputStandardFields> standard_fields{std::nullopt};
    std::vector<uint8_t> extra_data{};

    IMPL_SERIALIZABLE(OutputMessage, obj)
    {
        READWRITE(obj.features);

        if (obj.features & STANDARD_FIELDS_FEATURE_BIT) {
            OutputStandardFields standard_fields;
            SER_WRITE(obj, standard_fields = *obj.standard_fields);
            READWRITE(standard_fields);
            SER_READ(obj, obj.standard_fields = std::move(standard_fields));
        }

        if (obj.features & EXTRA_DATA_FEATURE_BIT) {
            READWRITE(obj.extra_data);
        }

        SER_READ(obj, obj.m_hash = Hashed(obj));
    }

    //
    // Traits
    //
    const mw::Hash& GetHash() const noexcept final { return m_hash; }

private:
    mw::Hash m_hash{};
};


class CompactOutput : public Traits::ISerializable
{
    Commitment m_commitment{};
    PublicKey m_senderPubKey{};
    PublicKey m_receiverPubKey{};
    OutputMessage m_message{};
    mw::Hash m_proof_hash{};
    Signature m_signature{};

    mw::Hash m_hash{};

public:
    //
    // Constructors
    //
    CompactOutput(
        Commitment commitment,
        PublicKey senderPubKey,
        PublicKey receiverPubKey,
        OutputMessage message,
        mw::Hash proof_hash,
        Signature signature
    ) :
        m_commitment(std::move(commitment)),
        m_senderPubKey(std::move(senderPubKey)),
        m_receiverPubKey(std::move(receiverPubKey)),
        m_message(std::move(message)),
        m_proof_hash(std::move(proof_hash)),
        m_signature(std::move(signature))
    {
        m_hash = ComputeHash();
    }

    CompactOutput(const CompactOutput& output) = default;
    CompactOutput(CompactOutput&& output) noexcept = default;
    CompactOutput() = default;
    

    //
    // Destructor
    //
    virtual ~CompactOutput() = default;

    //
    // Operators
    //
    CompactOutput& operator=(const CompactOutput& output) = default;
    CompactOutput& operator=(CompactOutput&& output) noexcept = default;
    bool operator<(const CompactOutput& output) const noexcept { return m_hash < output.m_hash; }
    bool operator==(const CompactOutput& output) const noexcept { return m_hash == output.m_hash; }

private:
    mw::Hash ComputeHash() const noexcept
    {
        return Hasher()
            .Append(m_commitment)
            .Append(m_senderPubKey)
            .Append(m_receiverPubKey)
            .Append(m_message.GetHash())
            .Append(m_proof_hash)
            .Append(m_signature)
            .hash();
    }
};

////////////////////////////////////////
// OUTPUT
////////////////////////////////////////
class Output :
    public Traits::ICommitted,
    public Traits::ISerializable,
    public Traits::IHashable,
    public Traits::IPrintable
{
public:
    //
    // Constructors
    //
    Output(
        Commitment commitment,
        PublicKey senderPubKey,
        PublicKey receiverPubKey,
        OutputMessage message,
        const RangeProof::CPtr& pProof,
        Signature signature
    ) :
        m_commitment(std::move(commitment)),
        m_senderPubKey(std::move(senderPubKey)),
        m_receiverPubKey(std::move(receiverPubKey)),
        m_message(std::move(message)),
        m_pProof(pProof),
        m_signature(std::move(signature))
    {
        m_hash = ComputeHash();
    }

    Output(const Output& Output) = default;
    Output(Output&& Output) noexcept = default;
    Output() = default;

    //
    // Factory
    //
    static Output Create(
        BlindingFactor* blind_out,
        const SecretKey& sender_privkey,
        const SecretKey& rewind_key,
        const StealthAddress& receiver_addr,
        const uint64_t value,
        const std::vector<uint8_t>& extra_data
    );

    //
    // Destructor
    //
    virtual ~Output() = default;

    //
    // Operators
    //
    Output& operator=(const Output& output) = default;
    Output& operator=(Output&& output) noexcept = default;
    bool operator<(const Output& output) const noexcept { return m_hash < output.m_hash; }
    bool operator==(const Output& output) const noexcept { return m_hash == output.m_hash; }

    //
    // Getters
    //
    const mw::Hash& GetOutputID() const noexcept { return m_hash; }
    const Commitment& GetCommitment() const noexcept final { return m_commitment; }
    const PublicKey& GetSenderPubKey() const noexcept { return m_senderPubKey; }
    const PublicKey& GetReceiverPubKey() const noexcept { return m_receiverPubKey; }
    const RangeProof::CPtr& GetRangeProof() const noexcept { return m_pProof; }
    const OutputMessage& GetOutputMessage() const noexcept { return m_message; }
    const Signature& GetSignature() const noexcept { return m_signature; }

    bool IsStandard() const noexcept
    {
        return m_message.features == OutputMessage::STANDARD_FIELDS_FEATURE_BIT
            && m_message.standard_fields.has_value()
            && m_message.standard_fields->key_exchange_pubkey.IsValid()
            && m_receiverPubKey.IsValid();
    }
    const std::vector<uint8_t>& GetExtraData() const noexcept { return m_message.extra_data; }
    uint8_t GetFeatures() const noexcept { return m_message.features; }
    bool HasStandardFields() const noexcept { return m_message.features & OutputMessage::STANDARD_FIELDS_FEATURE_BIT; }
    const PublicKey& GetKeyExchangePubKey() const noexcept { return m_message.standard_fields->key_exchange_pubkey; }
    uint8_t GetViewTag() const noexcept { return m_message.standard_fields->view_tag; }
    uint64_t GetMaskedValue() const noexcept { return m_message.standard_fields->masked_value; }
    const BigInt<16>& GetMaskedNonce() const noexcept { return m_message.standard_fields->masked_nonce; }

    const PublicKey& Ko() const noexcept { return m_receiverPubKey; }
    const PublicKey& Ke() const noexcept { return m_message.standard_fields->key_exchange_pubkey; }

    SignedMessage BuildSignedMsg() const noexcept;
    ProofData BuildProofData() const noexcept;

    //
    // Serialization/Deserialization
    //
    IMPL_SERIALIZABLE(Output, obj)
    {
        READWRITE(obj.m_commitment);
        READWRITE(obj.m_senderPubKey);
        READWRITE(obj.m_receiverPubKey);
        READWRITE(obj.m_message);
        READWRITE(obj.m_pProof);
        READWRITE(obj.m_signature);
        SER_READ(obj, obj.m_hash = obj.ComputeHash());
    }

    UniValue ToUni() const noexcept
    {
        UniValue uni(UniValue::VOBJ);
        uni.pushKV("commit", m_commitment.ToHex());
        uni.pushKV("sender_pk", m_senderPubKey.ToHex());
        uni.pushKV("receiver_pk", m_receiverPubKey.ToHex());
        uni.pushKV("features", static_cast<uint64_t>(m_message.features));

        if (m_message.features & OutputMessage::STANDARD_FIELDS_FEATURE_BIT) {
            uni.pushKV("key_exchange_pk", m_message.standard_fields->key_exchange_pubkey.ToHex());
            uni.pushKV("view_tag", static_cast<uint64_t>(m_message.standard_fields->view_tag));
            uni.pushKV("masked_value", static_cast<uint64_t>(m_message.standard_fields->masked_value));
            uni.pushKV("masked_nonce", m_message.standard_fields->masked_nonce.ToHex());
        }

        if (m_message.features & OutputMessage::EXTRA_DATA_FEATURE_BIT) {
            uni.pushKV("extra_data", HexStr(m_message.extra_data));
        }

        return uni;
    }

    //
    // Traits
    //
    std::string Format() const noexcept final { return "Output(ID=" + GetOutputID().Format() + ")"; }
    const mw::Hash& GetHash() const noexcept final { return m_hash; }

private:
    //
    // Outputs use a special serialization when hashing that only includes
    // the hash of the rangeproof, instead of the full 675 byte rangeproof.
    // 
    // This will make some light client use cases more efficient.
    //
    mw::Hash ComputeHash() const noexcept
    {
        return Hasher()
            .Append(m_commitment)
            .Append(m_senderPubKey)
            .Append(m_receiverPubKey)
            .Append(m_message.GetHash())
            .Append(m_pProof->GetHash())
            .Append(m_signature)
            .hash();
    }

    Commitment m_commitment{};
    PublicKey m_senderPubKey{};
    PublicKey m_receiverPubKey{};
    OutputMessage m_message{};
    RangeProof::CPtr m_pProof{};
    Signature m_signature{};

    mw::Hash m_hash{};
};

// Sorts by output ID (hash)
struct OutputSort
{
    bool operator()(const Output& a, const Output& b) const
    {
        return a.GetOutputID() < b.GetOutputID();
    }
};

END_NAMESPACE
