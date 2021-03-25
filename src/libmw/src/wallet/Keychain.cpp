#include <mw/wallet/Keychain.h>
#include <mw/crypto/Hasher.h>

MW_NAMESPACE

StealthAddress Keychain::GetStealthAddress(const uint32_t index) const
{
    assert(index < ULONG_MAX);
    m_addressIndexCounter = std::max(m_addressIndexCounter, index);

    PublicKey Bi = PublicKey::From(GetSpendKey(index));
    PublicKey Ai = Bi.Mul(m_scanSecret);

    return StealthAddress(Ai, Bi);
}

SecretKey Keychain::GetSpendKey(const uint32_t index) const
{
    assert(index < ULONG_MAX);
    m_addressIndexCounter = std::max(m_addressIndexCounter, index);

    SecretKey mi = Hasher(EHashTag::ADDRESS)
        .Append<uint32_t>(index)
        .Append(m_scanSecret)
        .hash();

    return Crypto::AddPrivateKeys(m_spendSecret, mi);
}

bool Keychain::IsSpendPubKey(const PublicKey& spend_pubkey, uint32_t& index_out) const
{
    // Ensure pubkey cache is fully populated
    while (m_pubkeys.size() < m_addressIndexCounter) {
        uint32_t pubkey_index = (uint32_t)m_pubkeys.size();
        PublicKey pubkey = PublicKey::From(GetSpendKey(pubkey_index));

        m_pubkeys.insert({ std::move(pubkey), pubkey_index });
    }

    auto iter = m_pubkeys.find(spend_pubkey);
    if (iter != m_pubkeys.end()) {
        index_out = iter->second;
        return true;
    }

    return false;
}

END_NAMESPACE