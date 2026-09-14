#pragma once

#include <mw/models/tx/Coin.h>
#include <memusage.h>
#include <unordered_map>

struct CoinAction
{
    bool IsSpend() const noexcept { return pCoin == nullptr; }

    size_t DynamicMemoryUsage() const noexcept
    {
        if (IsSpend()) return 0;
        const auto& output = pCoin->GetOutput();
        const auto& message = output.GetOutputMessage();
        const auto& proof = pCoin->GetRangeProof();
        // Conservatively charge shared coins and proofs per retained reference.
        size_t usage = memusage::DynamicUsage(pCoin) + memusage::DynamicUsage(output.GetExtraData()) +
            memusage::DynamicUsage(output.GetCommitment().vec()) +
            memusage::DynamicUsage(output.GetSenderPubKey().vec()) +
            memusage::DynamicUsage(output.GetReceiverPubKey().vec()) +
            memusage::DynamicUsage(output.GetSignature().vec()) +
            memusage::DynamicUsage(output.GetHash().vec()) + memusage::DynamicUsage(message.GetHash().vec());
        if (message.standard_fields) {
            usage += memusage::DynamicUsage(message.standard_fields->key_exchange_pubkey.vec()) +
                memusage::DynamicUsage(message.standard_fields->masked_nonce.vec());
        }
        if (proof) {
            usage += memusage::DynamicUsage(proof) + memusage::DynamicUsage(proof->vec()) +
                memusage::DynamicUsage(proof->GetHash().vec());
        }
        return usage;
    }

    mw::Coin::CPtr pCoin;
};

class CoinsViewUpdates
{
public:
    CoinsViewUpdates() = default;

    size_t DynamicMemoryUsage() const noexcept
    {
        return memusage::DynamicUsage(m_actions) + m_cachedUsage;
    }

    void AddCoin(const mw::Coin::CPtr& pCoin)
    {
        AddAction(pCoin->GetOutputID(), CoinAction{pCoin});
    }

    void SpendCoin(const mw::Hash& output_id)
    {
        AddAction(output_id, CoinAction{nullptr});
    }

    const std::unordered_map<mw::Hash, std::vector<CoinAction>>& GetActions() const noexcept { return m_actions; }

    std::vector<CoinAction> GetActions(const mw::Hash& output_id) const noexcept
    {
        auto iter = m_actions.find(output_id);
        if (iter != m_actions.cend()) {
            return iter->second;
        }

        return {};
    }

    void Clear() noexcept
    {
        // Release bucket storage too, so a flush can reclaim the cache budget.
        decltype(m_actions){}.swap(m_actions);
        m_cachedUsage = 0;
    }

private:
    void AddAction(const mw::Hash& output_id, CoinAction&& action)
    {
        auto [iter, inserted] = m_actions.try_emplace(output_id);
        if (inserted) m_cachedUsage += memusage::DynamicUsage(iter->first.vec());
        auto& actions = iter->second;
        const size_t old_usage = memusage::DynamicUsage(actions);
        actions.emplace_back(std::move(action));
        m_cachedUsage += memusage::DynamicUsage(actions) - old_usage + actions.back().DynamicMemoryUsage();
    }

    std::unordered_map<mw::Hash, std::vector<CoinAction>> m_actions;
    // Hash keys, action vector capacities, and recursively owned coin allocations.
    size_t m_cachedUsage{0};
};
