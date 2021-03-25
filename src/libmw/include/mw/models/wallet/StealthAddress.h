#pragma once

#include <mw/crypto/Keys.h>
#include <mw/models/crypto/PublicKey.h>
#include <mw/traits/Serializable.h>

class StealthAddress : public Traits::ISerializable
{
public:
    StealthAddress(PublicKey&& scan, PublicKey&& spend)
        : m_scan(std::move(scan)), m_spend(std::move(spend)) { }
    StealthAddress(const PublicKey& scan, const PublicKey& spend)
        : m_scan(scan), m_spend(spend) { }

    bool operator==(const StealthAddress& rhs) const noexcept
    {
        return m_scan == rhs.m_scan && m_spend == rhs.m_spend;
    }

    static StealthAddress Random()
    {
        return StealthAddress(Keys::Random().PubKey(), Keys::Random().PubKey());
    }

    const PublicKey& A() const noexcept { return m_scan; }
    const PublicKey& B() const noexcept { return m_spend; }

    const PublicKey& GetScanPubKey() const noexcept { return m_scan; }
    const PublicKey& GetSpendPubKey() const noexcept { return m_spend; }

    Serializer& Serialize(Serializer& serializer) const noexcept final
    {
        return serializer.Append(m_scan).Append(m_spend);
    }

    static StealthAddress Deserialize(Deserializer& deserializer)
    {
        PublicKey scan = PublicKey::Deserialize(deserializer);
        PublicKey spend = PublicKey::Deserialize(deserializer);
        return StealthAddress(std::move(scan), std::move(spend));
    }

private:
    PublicKey m_scan;
    PublicKey m_spend;
};