#include <mw/wallet/Wallet.h>
#include <mw/crypto/Keys.h>

bool Wallet::RewindOutput(const Output& output, libmw::Coin& coin) const
{
    SecretKey t = Hashed(EHashTag::DERIVE, output.Ke().Mul(m_pKeychain->GetScanSecret()));
    if (t[0] != output.GetViewTag()) {
        return false;
    }

    PublicKey B = output.Ko().Sub(Hashed(EHashTag::OUT_KEY, t));

    // Check if B belongs to wallet
    uint32_t index = 0;
    if (!m_pKeychain->IsSpendPubKey(B, index)) {
        return false;
    }

    StealthAddress wallet_addr = m_pKeychain->GetStealthAddress(index);
    Deserializer hash64(Hash512(t).vec());
    SecretKey r = hash64.Read<SecretKey>();
    uint64_t value = output.GetMaskedValue() ^ hash64.Read<uint64_t>();
    BigInt<16> n = output.GetMaskedNonce() ^ hash64.ReadVector(16);

    if (Commitment::Switch(r, value) != output.GetCommitment()) {
        return false;
    }

    // Calculate Carol's sending key 's' and check that s*B ?= Ke
    SecretKey s = Hasher(EHashTag::SEND_KEY)
        .Append(wallet_addr.A())
        .Append(wallet_addr.B())
        .Append(value)
        .Append(n)
        .hash();
    if (output.Ke() != wallet_addr.B().Mul(s)) {
        return false;
    }

    SecretKey private_key = Crypto::AddPrivateKeys(
        Hashed(EHashTag::OUT_KEY, t),
        m_pKeychain->GetSpendKey(index)
    );
    coin = libmw::Coin{
        output.GetFeatures().Get(),
        index,
        private_key.array(),
        r.array(),
        value,
        output.GetCommitment().array()
    };
    return true;
}