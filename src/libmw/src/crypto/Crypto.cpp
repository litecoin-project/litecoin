#include <mw/crypto/Crypto.h>
#include <mw/exceptions/CryptoException.h>
#include <mw/common/Logger.h>

#include <cassert>

// Secp256k1
#include "Context.h"
#include "Pedersen.h"
#include "PublicKeys.h"
#include <mw/crypto/Schnorr.h>
#include "ConversionUtil.h"

#ifdef _WIN32
#pragma comment(lib, "crypt32")
#endif

Locked<Context> SECP256K1_CONTEXT(std::make_shared<Context>());

Commitment Crypto::CommitTransparent(const uint64_t value)
{
    return Pedersen(SECP256K1_CONTEXT).PedersenCommit(value, BigInt<32>::ValueOf(0));
}

Commitment Crypto::CommitBlinded(
    const uint64_t value,
    const BlindingFactor& blindingFactor)
{
    return Pedersen(SECP256K1_CONTEXT).PedersenCommit(value, blindingFactor);
}

Commitment Crypto::AddCommitments(
    const std::vector<Commitment>& positive,
    const std::vector<Commitment>& negative)
{
    std::vector<Commitment> sanitizedPositive;
    std::copy_if(
        positive.cbegin(),
        positive.cend(),
        std::back_inserter(sanitizedPositive),
        [](const auto& positiveCommitment) {
            return !positiveCommitment.IsZero();
        }
    );

    std::vector<Commitment> sanitizedNegative;
    std::copy_if(
        negative.cbegin(),
        negative.cend(),
        std::back_inserter(sanitizedNegative),
        [](const auto& negativeCommitment) {
            return !negativeCommitment.IsZero();
        }
    );

    if (sanitizedPositive.empty() && sanitizedNegative.empty()) {
        return Commitment{};
    }

    return Pedersen(SECP256K1_CONTEXT).PedersenCommitSum(
        sanitizedPositive,
        sanitizedNegative
    );
}

BlindingFactor Crypto::AddBlindingFactors(
    const std::vector<BlindingFactor>& positive,
    const std::vector<BlindingFactor>& negative)
{
    BlindingFactor zeroBlindingFactor(ZERO_HASH);

    std::vector<BlindingFactor> sanitizedPositive;
    std::copy_if(
        positive.cbegin(),
        positive.cend(),
        std::back_inserter(sanitizedPositive),
        [&zeroBlindingFactor](const auto& positiveBlind) {
            return positiveBlind != zeroBlindingFactor;
        }
    );

    std::vector<BlindingFactor> sanitizedNegative;
    std::copy_if(
        negative.cbegin(),
        negative.cend(),
        std::back_inserter(sanitizedNegative),
        [&zeroBlindingFactor](const auto& negativeBlind) {
            return negativeBlind != zeroBlindingFactor;
        }
    );

    if (sanitizedPositive.empty() && sanitizedNegative.empty())
    {
        return zeroBlindingFactor;
    }

    return Pedersen(SECP256K1_CONTEXT).PedersenBlindSum(sanitizedPositive, sanitizedNegative);
}

BlindingFactor Crypto::BlindSwitch(const BlindingFactor& secretKey, const uint64_t amount)
{
    return Pedersen(SECP256K1_CONTEXT).BlindSwitch(secretKey, amount);
}

SecretKey Crypto::AddPrivateKeys(const SecretKey& secretKey1, const SecretKey& secretKey2)
{
    SecretKey result(secretKey1.vec());

    const int tweakResult = secp256k1_ec_privkey_tweak_add(
        SECP256K1_CONTEXT.Read()->Get(),
        (uint8_t*)result.data(),
        secretKey2.data()
    );
    if (tweakResult == 1)
    {
        return result;
    }

    ThrowCrypto("secp256k1_ec_privkey_tweak_add failed");
}

PublicKey Crypto::CalculatePublicKey(const BigInt<32>& privateKey)
{
    return PublicKeys(SECP256K1_CONTEXT).CalculatePublicKey(privateKey);
}

PublicKey Crypto::AddPublicKeys(const std::vector<PublicKey>& publicKeys, const std::vector<PublicKey>& subtract)
{
    return PublicKeys(SECP256K1_CONTEXT).PublicKeySum(publicKeys, subtract);
}

PublicKey Crypto::ToPublicKey(const Commitment& commitment)
{
    return ConversionUtil(SECP256K1_CONTEXT).ToPublicKey(commitment);
}

PublicKey Crypto::MultiplyKey(const PublicKey& public_key, const SecretKey& mul)
{
    secp256k1_pubkey pubkey = ConversionUtil(SECP256K1_CONTEXT).ToSecp256k1(public_key);
    const int tweakResult = secp256k1_ec_pubkey_tweak_mul(
        SECP256K1_CONTEXT.Read()->Get(),
        &pubkey,
        mul.data()
    );
    if (tweakResult == 1) {
        return ConversionUtil(SECP256K1_CONTEXT).ToPublicKey(pubkey);
    }

    ThrowCrypto("secp256k1_ec_pubkey_tweak_mul failed");
}