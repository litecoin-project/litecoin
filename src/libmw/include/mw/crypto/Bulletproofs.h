#pragma once

#include <mw/models/crypto/BigInteger.h>
#include <mw/models/crypto/Commitment.h>
#include <mw/models/crypto/ProofData.h>
#include <mw/models/crypto/RangeProof.h>
#include <mw/models/crypto/SecretKey.h>
#include <memory>
#include <utility>

class Bulletproofs
{
public:
    static bool BatchVerify(
        const std::vector<ProofData>& rangeProofs
    );

    static RangeProof::CPtr Generate(
        const uint64_t amount,
        const SecretKey& key,
        const SecretKey& sharedNonce,
        const SecretKey& privateNonce,
        const BigInt<32>& sharedMessage,
        const BigInt<32>& privateMessage,
        const std::vector<uint8_t>& extraData
    );

    static std::pair<BigInt<32>, BigInt<32>> Rewind(
        const Commitment& commitment,
        const RangeProof& rangeProof,
        const std::vector<uint8_t>& extraData,
        const SecretKey& sharedNonce,
        const SecretKey& privateNonce
    );
};
