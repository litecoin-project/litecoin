#pragma once

#include "Context.h"

#include <mw/models/crypto/BlindingFactor.h>
#include <mw/models/crypto/Commitment.h>

class Pedersen
{
public:
    Pedersen(Locked<Context>& context) : m_context(context) { }
    ~Pedersen() = default;

    Commitment PedersenCommit(
        const uint64_t value,
        const BlindingFactor& blindingFactor
    ) const;

    Commitment PedersenCommitSum(
        const std::vector<Commitment>& positive,
        const std::vector<Commitment>& negative
    ) const;

    BlindingFactor PedersenBlindSum(
        const std::vector<BlindingFactor>& positive,
        const std::vector<BlindingFactor>& negative
    ) const;

    BlindingFactor BlindSwitch(
        const BlindingFactor& secretKey,
        const uint64_t amount
    ) const;

private:
    Locked<Context> m_context;
};