#include <mw/node/BlockValidator.h>
#include <mw/exceptions/ValidationException.h>
#include <logging.h>
#include <set>
#include <unordered_map>

bool BlockValidator::ValidateBlock(
    const mw::Block::CPtr& pBlock,
    const std::vector<PegInCoin>& pegInCoins,
    const std::vector<PegOutCoin>& pegOutCoins) noexcept
{
    assert(pBlock != nullptr);

    std::optional<EConsensusError> error = pBlock->Validate();
    if (!error) {
        error = ValidatePegInCoins(pBlock, pegInCoins);
    }
    if (!error) {
        error = ValidatePegOutCoins(pBlock, pegOutCoins);
    }

    if (error) {
        LogPrintf("Failed to validate %s. Error: %s\n", pBlock->Format(), ConsensusErrorString(*error));
        return false;
    }

    return true;
}

std::optional<EConsensusError> BlockValidator::ValidatePegInCoins(
    const mw::Block::CPtr& pBlock,
    const std::vector<PegInCoin>& pegInCoins) noexcept
try {
    std::unordered_map<mw::Hash, CAmount> pegInAmounts;
    for (const PegInCoin& coin : pegInCoins) {
        auto inserted = pegInAmounts.insert({coin.GetKernelID(), coin.GetAmount()});
        if (!inserted.second) {
            return EConsensusError::PEGIN_MISMATCH;
        }
    }

    auto pegin_coins = pBlock->GetPegIns();
    if (pegin_coins.size() != pegInAmounts.size()) {
        return EConsensusError::PEGIN_MISMATCH;
    }

    for (const auto& pegin : pegin_coins) {
        auto pIter = pegInAmounts.find(pegin.GetKernelID());
        if (pIter == pegInAmounts.end() || pegin.GetAmount() != pIter->second) {
            return EConsensusError::PEGIN_MISMATCH;
        }

        pegInAmounts.erase(pIter);
    }

    return std::nullopt;
} catch (const std::exception&) {
    return EConsensusError::PEGIN_MISMATCH;
}

std::optional<EConsensusError> BlockValidator::ValidatePegOutCoins(
    const mw::Block::CPtr& pBlock,
    const std::vector<PegOutCoin>& pegOutCoins) noexcept
try {
    std::vector<PegOutCoin> mweb_pegouts = pBlock->GetPegOuts();
    if (mweb_pegouts.size() != pegOutCoins.size()) {
        return EConsensusError::PEGOUT_MISMATCH;
    }

    // We use a multiset since there can be multiple pegouts with the same scriptPubKey and amount.
    std::multiset<PegOutCoin> hogex_pegouts(pegOutCoins.begin(), pegOutCoins.end());
    for (const auto& pegout : mweb_pegouts) {
        auto iter = hogex_pegouts.find(pegout);
        if (iter == hogex_pegouts.end()) {
            return EConsensusError::PEGOUT_MISMATCH;
        }

        hogex_pegouts.erase(iter);
    }

    return std::nullopt;
} catch (const std::exception&) {
    return EConsensusError::PEGOUT_MISMATCH;
}
