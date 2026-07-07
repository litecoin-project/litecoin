// Copyright (c) 2011-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifdef HAVE_CONFIG_H
#include <config/bitcoin-config.h>
#endif

#include <qt/walletmodeltransaction.h>

#include <policy/policy.h>
#include <wallet/change.h>

WalletModelTransaction::WalletModelTransaction(const QList<SendCoinsRecipient> &_recipients) :
    recipients(_recipients),
    fee(0)
{
}

QList<SendCoinsRecipient> WalletModelTransaction::getRecipients() const
{
    return recipients;
}

CTransactionRef& WalletModelTransaction::getWtx()
{
    return wtx;
}

void WalletModelTransaction::setWtx(const CTransactionRef& newTx)
{
    wtx = newTx;
}

unsigned int WalletModelTransaction::getTransactionSize()
{
    return wtx ? GetVirtualTransactionSize(*wtx) : 0;
}

CAmount WalletModelTransaction::getTransactionFee() const
{
    return fee;
}

void WalletModelTransaction::setTransactionFee(const CAmount& newFee)
{
    fee = newFee;
}

void WalletModelTransaction::reassignAmounts(interfaces::Wallet& wallet, const wallet::ChangePosition& change_pos)
{
    std::vector<AnyOutput> outputs = wtx->GetOutputs();
    std::vector<PegOutCoin> pegouts = wtx->mweb_tx.GetPegOuts();

    size_t i = 0;
    for (QList<SendCoinsRecipient>::iterator it = recipients.begin(); it != recipients.end(); ++it)
    {
        SendCoinsRecipient& rcp = (*it);
        {
            while (i < outputs.size()) {
                const AnyOutput& output = outputs[i];
                const bool is_ltc_change = change_pos.IsLTC() && !output.IsMWEB() && i == change_pos.ToLTC();
                bool is_mweb_change{false};
                if (change_pos.IsMWEB() && output.IsMWEB()) {
                    const auto& mweb_change = change_pos.ToMWEB();
                    is_mweb_change = mweb_change.hash ? output.GetID() == *mweb_change.hash : i == wtx->vout.size() + mweb_change.idx;
                }

                if (is_ltc_change || is_mweb_change || (!output.IsMWEB() && output.GetScriptPubKey().IsMWEBPegin())) {
                    i++;
                } else {
                    break;
                }
            }

            if (i < outputs.size()) {
                rcp.amount = wallet.getValue(outputs[i]);
            } else if (pegouts.size() > (i - outputs.size())) {
                rcp.amount = pegouts[i - outputs.size()].GetAmount();
            }

            i++;
        }
    }
}

CAmount WalletModelTransaction::getTotalTransactionAmount() const
{
    CAmount totalTransactionAmount = 0;
    for (const SendCoinsRecipient &rcp : recipients)
    {
        totalTransactionAmount += rcp.amount;
    }
    return totalTransactionAmount;
}
