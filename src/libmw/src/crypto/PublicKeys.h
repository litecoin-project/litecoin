#pragma once

#include "Context.h"

#include <mw/models/crypto/BigInteger.h>
#include <mw/models/crypto/PublicKey.h>

class PublicKeys
{
public:
    PublicKeys(Locked<Context>& context) : m_context(context) { }
    ~PublicKeys() = default;

    PublicKey CalculatePublicKey(const BigInt<32>& privateKey) const;
    PublicKey PublicKeySum(
        const std::vector<PublicKey>& publicKeys,
        const std::vector<PublicKey>& subtract
    ) const;

private:
    Locked<Context> m_context;
};