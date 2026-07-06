// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/coin.h>

#include <node/context.h>
#include <txmempool.h>
#include <validation.h>

namespace node {
void FindCoins(const NodeContext& node, std::map<AnyOutputID, AnyCoin>& coins)
{
    assert(node.mempool);
    assert(node.chainman);
    LOCK2(cs_main, node.mempool->cs);
    CCoinsViewCache& chain_view = node.chainman->ActiveChainstate().CoinsTip();
    CCoinsViewMemPool mempool_view(&chain_view, *node.mempool);
    for (auto& coin_it : coins) {
        if (coin_it.first.IsMWEB()) {
            mw::Coin::CPtr coin{nullptr};
            if (!mempool_view.GetMWEBCoin(coin_it.first.ToMWEB(), coin)) {
                coin = nullptr;
            }

            coin_it.second = AnyCoin(coin);
        } else {
            const COutPoint& outpoint = coin_it.first.ToOutPoint();
            Coin coin;
            if (!mempool_view.GetCoin(outpoint, coin)) {
                // Either the coin is not in the CCoinsViewCache or is spent. Clear it.
                coin.Clear();
            }

            coin_it.second = AnyCoin(outpoint, std::move(coin));
        }
    }
}

void FindCoins(const NodeContext& node, std::map<COutPoint, Coin>& coins)
{
    assert(node.mempool);
    assert(node.chainman);
    LOCK2(cs_main, node.mempool->cs);
    CCoinsViewCache& chain_view = node.chainman->ActiveChainstate().CoinsTip();
    CCoinsViewMemPool mempool_view(&chain_view, *node.mempool);
    for (auto& coin : coins) {
        if (!mempool_view.GetCoin(coin.first, coin.second)) {
            coin.second.Clear();
        }
    }
}
} // namespace node
