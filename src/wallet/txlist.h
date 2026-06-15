#pragma once

#include <script/address.h>
#include <wallet/txrecord.h>
#include <wallet/ismine.h>
#include <optional>

// Forward Declarations
class AnyOutput;

namespace wallet {

class CWallet;
class CWalletTx;

class TxList
{
    const CWallet& m_wallet;

public:
    TxList(const CWallet& wallet)
        : m_wallet(wallet) {}

    std::vector<WalletTxRecord> ListAll(const wallet::isminefilter& filter_ismine = wallet::ISMINE_ALL);
    std::vector<WalletTxRecord> List(
        const CWalletTx& wtx,
        const wallet::isminefilter& filter_ismine,
        const std::optional<int>& nMinDepth,
        const std::optional<std::string>& filter_label);

private:
    void List(std::vector<WalletTxRecord>& tx_records, const CWalletTx& wtx, const wallet::isminefilter& filter_ismine);

    void List_Credit(std::vector<WalletTxRecord>& tx_records, const CWalletTx& wtx, const wallet::isminefilter& filter_ismine);
    void List_Debit(std::vector<WalletTxRecord>& tx_records, const CWalletTx& wtx, const wallet::isminefilter& filter_ismine);
    void List_SelfSend(std::vector<WalletTxRecord>& tx_records, const CWalletTx& wtx, const wallet::isminefilter& filter_ismine);

    wallet::isminetype IsAddressMine(const CWalletTx& wtx, const AnyOutput& txout);
    GenericAddress GetAddress(const AnyOutput& output);
    bool IsAllFromMe(const CWalletTx& wtx);
    bool IsAllToMe(const CWalletTx& wtx);
    bool IsMine(const CWalletTx& wtx);
};

} // namespace wallet
