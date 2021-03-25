#include <mw/models/tx/Kernel.h>
#include <mw/crypto/Schnorr.h>

static const uint8_t FEE_FEATURE_BIT = 0x01;
static const uint8_t PEGIN_FEATURE_BIT = 0x02;
static const uint8_t PEGOUT_FEATURE_BIT = 0x04;
static const uint8_t HEIGHT_LOCK_FEATURE_BIT = 0x08;
static const uint8_t EXTRA_DATA_FEATURE_BIT = 0x10;

Kernel Kernel::Create(
    const BlindingFactor& blind,
    const boost::optional<uint64_t>& fee,
    const boost::optional<uint64_t>& pegin_amount,
    const boost::optional<PegOutCoin>& pegout,
    const boost::optional<uint64_t>& lock_height)
{
    Commitment excess_commit = Commitment::Blinded(blind, 0);

    mw::Hash sig_message = Kernel::GetSignatureMessage(fee, pegin_amount, pegout, lock_height, {});
    Signature sig = Schnorr::Sign(blind.data(), sig_message);

    return Kernel(
        fee,
        pegin_amount,
        pegout,
        lock_height,
        std::vector<uint8_t>{},
        std::move(excess_commit),
        std::move(sig)
    );
}

mw::Hash Kernel::GetSignatureMessage() const
{
    return Kernel::GetSignatureMessage(m_fee, m_pegin, m_pegout, m_lockHeight, m_extraData);
}

mw::Hash Kernel::GetSignatureMessage(
    const boost::optional<uint64_t>& fee,
    const boost::optional<uint64_t>& pegin_amount,
    const boost::optional<PegOutCoin>& pegout,
    const boost::optional<uint64_t>& lock_height,
    const std::vector<uint8_t>& extra_data)
{
    uint8_t features_byte =
        (fee.has_value() ? FEE_FEATURE_BIT : 0) |
        (pegin_amount.has_value() ? PEGIN_FEATURE_BIT : 0) |
        (pegout.has_value() ? PEGOUT_FEATURE_BIT : 0) |
        (lock_height.has_value() ? HEIGHT_LOCK_FEATURE_BIT : 0) |
        (extra_data.size() > 0 ? EXTRA_DATA_FEATURE_BIT : 0);

    Hasher sig_message_hasher = Hasher();
    sig_message_hasher.Append<uint8_t>(features_byte);

    if (fee.has_value()) {
        sig_message_hasher.Append<uint64_t>(fee.value());
    }

    if (pegin_amount.has_value()) {
        sig_message_hasher.Append<uint64_t>(pegin_amount.value());
    }

    if (pegout.has_value()) {
        sig_message_hasher
            .Append<uint64_t>(pegout.value().GetAmount())
            .Append(pegout.value().GetScriptPubKey());
    }

    if (lock_height.has_value()) {
        sig_message_hasher.Append<uint64_t>(lock_height.value());
    }

    if (!extra_data.empty()) {
        sig_message_hasher.Append(extra_data);
    }

    return sig_message_hasher.hash();
}

Serializer& Kernel::Serialize(Serializer& serializer) const noexcept
{
    uint8_t features_byte =
        (m_fee.has_value() ? FEE_FEATURE_BIT : 0) |
        (m_pegin.has_value() ? PEGIN_FEATURE_BIT : 0) |
        (m_pegout.has_value() ? PEGOUT_FEATURE_BIT : 0) |
        (m_lockHeight.has_value() ? HEIGHT_LOCK_FEATURE_BIT : 0) |
        (m_extraData.size() > 0 ? EXTRA_DATA_FEATURE_BIT : 0);

    serializer.Append<uint8_t>(features_byte);

    if (m_fee.has_value()) {
        serializer.Append<uint64_t>(m_fee.value());
    }

    if (m_pegin.has_value()) {
        serializer.Append<uint64_t>(m_pegin.value());
    }

    if (m_pegout.has_value()) {
        serializer
            .Append<uint64_t>(m_pegout.value().GetAmount())
            .Append<uint8_t>((uint8_t)m_pegout.value().GetScriptPubKey().size())
            .Append(m_pegout.value().GetScriptPubKey());
    }

    if (m_lockHeight.has_value()) {
        serializer.Append<uint64_t>(m_lockHeight.value());
    }

    if (!m_extraData.empty()) {
        serializer
            .Append<uint8_t>((uint8_t)m_extraData.size())
            .Append(m_extraData);
    }

    serializer
        .Append(m_excess)
        .Append(m_signature);

    return serializer;
}

Kernel Kernel::Deserialize(Deserializer& deserializer)
{
    uint8_t features = deserializer.Read<uint8_t>();

    boost::optional<uint64_t> fee = boost::none;
    if (features & FEE_FEATURE_BIT) {
        fee = deserializer.Read<uint64_t>();
    }

    boost::optional<uint64_t> pegin = boost::none;
    if (features & PEGIN_FEATURE_BIT) {
        pegin = deserializer.Read<uint64_t>();
    }

    boost::optional<PegOutCoin> pegout = boost::none;
    if (features & PEGOUT_FEATURE_BIT) {
        uint64_t amount = deserializer.Read<uint64_t>();
        uint8_t num_bytes = deserializer.Read<uint8_t>();
        std::vector<uint8_t> scriptPubKey = deserializer.ReadVector(num_bytes);
        pegout = PegOutCoin(amount, std::move(scriptPubKey));
    }

    boost::optional<uint64_t> lock_height = boost::none;
    if (features & HEIGHT_LOCK_FEATURE_BIT) {
        lock_height = deserializer.Read<uint64_t>();
    }

    std::vector<uint8_t> extra_data;
    if (features & EXTRA_DATA_FEATURE_BIT) {
        uint8_t num_bytes = deserializer.Read<uint8_t>();
        extra_data = deserializer.ReadVector(num_bytes);
    }

    Commitment excess = Commitment::Deserialize(deserializer);
    Signature signature = Signature::Deserialize(deserializer);

    return Kernel{
        std::move(fee),
        std::move(pegin),
        std::move(pegout),
        std::move(lock_height),
        std::move(extra_data),
        std::move(excess),
        std::move(signature)
    };
}