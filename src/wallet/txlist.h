#pragma once

#include <script/address.h>
#include <wallet/txrecord.h>
#include <wallet/ismine.h>
#include <wallet/wallet.h>
#include <optional>

// Forward Declarations
class AnyOutput;

namespace wallet {

class TxList
{
    const CWallet& m_wallet;

public:
    TxList(const CWallet& wallet)
        : m_wallet(wallet) {}

    std::vector<WalletTxRecord> ListAll(const wallet::isminefilter& filter_ismine = wallet::ISMINE_ALL) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet);
    std::vector<WalletTxRecord> List(
        const CWalletTx& wtx,
        const wallet::isminefilter& filter_ismine,
        const std::optional<int>& nMinDepth,
        const std::optional<std::string>& filter_label) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet);

private:
    void List(std::vector<WalletTxRecord>& tx_records, const CWalletTx& wtx, const wallet::isminefilter& filter_ismine) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet);

    void List_Credit(std::vector<WalletTxRecord>& tx_records, const CWalletTx& wtx, const wallet::isminefilter& filter_ismine) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet);
    void List_Debit(std::vector<WalletTxRecord>& tx_records, const CWalletTx& wtx, const wallet::isminefilter& filter_ismine) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet);
    void List_SelfSend(std::vector<WalletTxRecord>& tx_records, const CWalletTx& wtx, const wallet::isminefilter& filter_ismine) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet);

    wallet::isminetype IsAddressMine(const CWalletTx& wtx, const AnyOutput& txout) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet);
    GenericAddress GetAddress(const AnyOutput& output) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet);
    bool IsAllFromMe(const CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet);
    bool IsAllToMe(const CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet);
    bool IsMine(const CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet);
};

} // namespace wallet
