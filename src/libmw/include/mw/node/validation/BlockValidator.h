#pragma once

#include <mw/models/block/Block.h>

class BlockValidator
{
public:
    BlockValidator() = default;

    void Validate(
        const mw::Block::Ptr& pBlock,
        const mw::Hash& mweb_hash,
        const std::vector<PegInCoin>& pegInCoins,
        const std::vector<PegOutCoin>& pegOutCoins
    );

private:
    void ValidatePegInCoins(
        const mw::Block::CPtr& pBlock,
        const std::vector<PegInCoin>& pegInCoins
    );

    void ValidatePegOutCoins(
        const mw::Block::CPtr& pBlock,
        const std::vector<PegOutCoin>& pegOutCoins
    );
};