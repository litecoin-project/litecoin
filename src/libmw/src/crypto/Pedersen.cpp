#include "Pedersen.h"
#include "ConversionUtil.h"

#include <mw/exceptions/CryptoException.h>
#include <mw/common/Logger.h>
#include <mw/util/VectorUtil.h>

Commitment Pedersen::PedersenCommit(const uint64_t value, const BlindingFactor& blindingFactor) const
{
    secp256k1_pedersen_commitment commitment;
    const int result = secp256k1_pedersen_commit(
        m_context.Read()->Get(),
        &commitment,
        blindingFactor.data(),
        value,
        &secp256k1_generator_const_h,
        &secp256k1_generator_const_g
    );
    if (result != 1) {
        ThrowCrypto("Failed to create commitment.");
    }

    return ConversionUtil(m_context).ToCommitment(commitment);
}

Commitment Pedersen::PedersenCommitSum(const std::vector<Commitment>& positive, const std::vector<Commitment>& negative) const
{
    std::vector<secp256k1_pedersen_commitment> positiveCommitments = ConversionUtil(m_context).ToSecp256k1(positive);
    std::vector<secp256k1_pedersen_commitment*> positivePtrs = VectorUtil::ToPointerVec(positiveCommitments);

    std::vector<secp256k1_pedersen_commitment> negativeCommitments = ConversionUtil(m_context).ToSecp256k1(negative);
    std::vector<secp256k1_pedersen_commitment*> negativePtrs = VectorUtil::ToPointerVec(negativeCommitments);

    secp256k1_pedersen_commitment commitment;
    const int result = secp256k1_pedersen_commit_sum(
        m_context.Read()->Get(),
        &commitment,
        positivePtrs.empty() ? nullptr : positivePtrs.data(),
        positivePtrs.size(),
        negativePtrs.empty() ? nullptr : negativePtrs.data(),
        negativePtrs.size()
    );

    if (result != 1) {
        ThrowCrypto("secp256k1_pedersen_commit_sum error");
    }

    return ConversionUtil(m_context).ToCommitment(commitment);
}

BlindingFactor Pedersen::PedersenBlindSum(const std::vector<BlindingFactor>& positive, const std::vector<BlindingFactor>& negative) const
{
    std::vector<const unsigned char*> blindingFactors;
    for (const BlindingFactor& positiveFactor : positive)
    {
        blindingFactors.push_back(positiveFactor.data());
    }

    for (const BlindingFactor& negativeFactor : negative)
    {
        blindingFactors.push_back(negativeFactor.data());
    }

    BlindingFactor blindingFactor;
    const int result = secp256k1_pedersen_blind_sum(
        m_context.Read()->Get(),
        blindingFactor.data(),
        blindingFactors.data(),
        blindingFactors.size(),
        positive.size()
    );
    if (result != 1) {
        ThrowCrypto("secp256k1_pedersen_blind_sum error");
    }

    return blindingFactor;
}

BlindingFactor Pedersen::BlindSwitch(const BlindingFactor& blindingFactor, const uint64_t amount) const
{
    BlindingFactor blindSwitch;
    const int result = secp256k1_blind_switch(
        m_context.Read()->Get(),
        blindSwitch.data(),
        blindingFactor.data(),
        amount,
        &secp256k1_generator_const_h,
        &secp256k1_generator_const_g,
        &GENERATOR_J_PUB
    );
    if (result != 1) {
        ThrowCrypto("secp256k1_blind_switch failed");
    }

    return blindSwitch;
}