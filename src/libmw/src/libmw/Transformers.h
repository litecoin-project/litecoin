#pragma once

#include <libmw/libmw.h>
#include <mw/models/tx/PegInCoin.h>
#include <mw/models/tx/PegOutCoin.h>
#include <mw/models/tx/Transaction.h>
#include <mw/models/block/Block.h>
#include <mw/models/wallet/StealthAddress.h>

static mw::Hash TransformHash(const libmw::BlockHash& hash)
{
    return mw::Hash(hash);
}

static std::vector<PegInCoin> TransformPegIns(const std::vector<libmw::PegIn>& pegInCoins)
{
    std::vector<PegInCoin> pegins;
    std::transform(
        pegInCoins.cbegin(), pegInCoins.cend(),
        std::back_inserter(pegins),
        [](const libmw::PegIn& pegin) { return PegInCoin{ pegin.amount, Commitment{ pegin.commitment } }; }
    );

    return pegins;
}

static std::vector<PegOutCoin> TransformPegOuts(const std::vector<libmw::PegOut>& pegOutCoins)
{
    std::vector<PegOutCoin> pegouts;
    std::transform(
        pegOutCoins.cbegin(), pegOutCoins.cend(),
        std::back_inserter(pegouts),
        [](const libmw::PegOut& pegout) { return PegOutCoin{ pegout.amount, pegout.scriptPubKey }; }
    );

    return pegouts;
}

static std::vector<mw::Transaction::CPtr> TransformTxs(const std::vector<libmw::TxRef>& txs)
{
    std::vector<mw::Transaction::CPtr> transactions;
    std::transform(
        txs.cbegin(), txs.cend(),
        std::back_inserter(transactions),
        [](const libmw::TxRef& tx) { return tx.pTransaction; }
    );

    return transactions;
}

static libmw::MWEBAddress TransformAddress(const StealthAddress& address)
{
    return std::make_pair(address.GetScanPubKey().array(), address.GetSpendPubKey().array());
}

static StealthAddress TransformAddress(const libmw::MWEBAddress& address)
{
    return StealthAddress(
        PublicKey{ address.first },
        PublicKey{ address.second }
    );
}