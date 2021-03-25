#include <mw/models/crypto/PublicKey.h>
#include <mw/models/crypto/SecretKey.h>
#include <mw/crypto/Crypto.h>

PublicKey PublicKey::From(const SecretKey& key)
{
    return Crypto::CalculatePublicKey(key.GetBigInt());
}

PublicKey PublicKey::Mul(const SecretKey& mul) const
{
    return Crypto::MultiplyKey(*this, mul);
}

PublicKey PublicKey::Add(const SecretKey& add) const
{
    return Crypto::AddPublicKeys({ *this, PublicKey::From(add) });
}

PublicKey PublicKey::Add(const PublicKey& add) const
{
    return Crypto::AddPublicKeys({ *this, add });
}

PublicKey PublicKey::Sub(const SecretKey& sub) const
{
    return Crypto::AddPublicKeys({ *this }, { PublicKey::From(sub) });
}

PublicKey PublicKey::Sub(const PublicKey& sub) const
{
    return Crypto::AddPublicKeys({ *this }, { sub });
}