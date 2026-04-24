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
        const SecretKey& nonce,
        const BigInt<32>& message,
        const std::vector<uint8_t>& extraData
    );

    static BigInt<32> Rewind(
        const Commitment& commitment,
        const RangeProof& rangeProof,
        const std::vector<uint8_t>& extraData,
        const SecretKey& nonce
    );
};
