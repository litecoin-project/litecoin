#pragma once

#include <mw/models/block/Block.h>

#include <optional>

class BlockValidator
{
public:
    BlockValidator() = default;

    static bool ValidateBlock(
        const mw::Block::CPtr& pBlock,
        const std::vector<PegInCoin>& pegInCoins,
        const std::vector<PegOutCoin>& pegOutCoins
    ) noexcept;

private:
    [[nodiscard]] static std::optional<EConsensusError> ValidatePegInCoins(
        const mw::Block::CPtr& pBlock,
        const std::vector<PegInCoin>& pegInCoins
    ) noexcept;

    [[nodiscard]] static std::optional<EConsensusError> ValidatePegOutCoins(
        const mw::Block::CPtr& pBlock,
        const std::vector<PegOutCoin>& pegOutCoins
    ) noexcept;
};