#include <wallet/receive.h>
#include <mweb/mweb_wallet.h>
#include <wallet/txlist.h>
#include <wallet/wallet.h>
#include <key_io.h>

namespace wallet {

std::vector<WalletTxRecord> TxList::ListAll(const wallet::isminefilter& filter_ismine)
{
    std::vector<WalletTxRecord> tx_records;
    for (const auto& entry : m_wallet.mapWallet) {
        List(tx_records, entry.second, filter_ismine);
    }

    return tx_records;
}

std::vector<WalletTxRecord> TxList::List(const CWalletTx& wtx, const wallet::isminefilter& filter_ismine, const std::optional<int>& nMinDepth, const std::optional<std::string>& filter_label)
{
    std::vector<WalletTxRecord> tx_records;
    List(tx_records, wtx, filter_ismine);

    auto iter = tx_records.begin();
    while (iter != tx_records.end()) {
        if (iter->credit > 0) {
            // Filter received transactions
            if (nMinDepth && m_wallet.GetTxDepthInMainChain(wtx) < *nMinDepth) {
                iter = tx_records.erase(iter);
                continue;
            }

            if (filter_label) {
                std::string label;

                CTxDestination destination = DecodeDestination(iter->address);
                if (IsValidDestination(destination)) {
                    const auto* address_book_entry = m_wallet.FindAddressBookEntry(destination);
                    if (address_book_entry) {
                        label = address_book_entry->GetLabel();
                    }
                }

                if (label != *filter_label) {
                    iter = tx_records.erase(iter);
                    continue;
                }
            }
        } else {
            // Filter sent transactions
            if (filter_label) {
                iter = tx_records.erase(iter);
                continue;
            }
        }

        iter++;
    }

    return tx_records;
}

void TxList::List(std::vector<WalletTxRecord>& tx_records, const CWalletTx& wtx, const wallet::isminefilter& filter_ismine)
{
    CAmount nCredit = CachedTxGetCredit(m_wallet, wtx, filter_ismine);
    CAmount nDebit = CachedTxGetDebit(m_wallet, wtx, filter_ismine);
    CAmount nNet = nCredit - nDebit;

    if (!IsMine(wtx)) {
        return;
    }

    if (nNet > 0 || wtx.IsCoinBase() || wtx.IsHogEx()) {
        // Credit
        List_Credit(tx_records, wtx, filter_ismine);
    } else if (AllInputsMine(m_wallet, wtx, filter_ismine)) {
        if (IsAllToMe(wtx)) {
            // Payment to Self
            List_SelfSend(tx_records, wtx, filter_ismine);
        } else {
            // Debit
            List_Debit(tx_records, wtx, filter_ismine);
        }
    } else {
        // Mixed debit transaction, can't break down payees
        WalletTxRecord tx_record(&m_wallet, &wtx);
        tx_record.type = WalletTxRecord::Type::Other;
        tx_record.debit = nNet;
        tx_records.push_back(std::move(tx_record));
    }
}

void TxList::List_Credit(std::vector<WalletTxRecord>& tx_records, const CWalletTx& wtx, const wallet::isminefilter& filter_ismine)
{
    std::vector<AnyOutput> outputs = wtx.GetTxOutputs();
    for (size_t i = 0; i < outputs.size(); i++) {
        const AnyOutput& output = outputs[i];
        if (!output.IsMWEB() && output.GetScriptPubKey().IsMWEBPegin()) {
            continue;
        }

        wallet::isminetype ismine = m_wallet.IsMine(output);
        if (ismine & filter_ismine) {
            // Skip displaying hog-ex outputs when we have the MWEB transaction that contains the pegout.
            // The original MWEB transaction will be displayed instead.
            if (wtx.IsHogEx() && wtx.pegout_indices.size() > i) {
                mw::Hash kernel_id = wtx.pegout_indices[i].first;
                if (m_wallet.FindWalletTxByKernelId(kernel_id) != nullptr) {
                    continue;
                }
            }

            WalletTxRecord sub(&m_wallet, &wtx, output.GetID());
            sub.credit = m_wallet.GetValue(output);
            sub.involvesWatchAddress = ismine & ISMINE_WATCH_ONLY;

            if (IsAddressMine(wtx, output)) {
                // Received by Litecoin Address
                sub.type = WalletTxRecord::Type::RecvWithAddress;
                sub.address = GetAddress(output).Encode();
            } else {
                // Received by IP connection (deprecated features), or a multisignature or other non-simple transaction
                sub.type = WalletTxRecord::Type::RecvFromOther;
                sub.address = wtx.mapValue.count("from") > 0 ? wtx.mapValue.at("from") : "";
            }

            if (wtx.IsCoinBase()) {
                sub.type = WalletTxRecord::Type::Generated;
            }

            tx_records.push_back(sub);
        }
    }

    std::optional<mw::WalletCoin> mweb_coin = wtx.GetMWEBReceivedCoin();
    if (mweb_coin != std::nullopt) {
        wallet::isminetype ismine = m_wallet.IsMine(mweb_coin->output_id);
        if (ismine & filter_ismine) {
            WalletTxRecord sub(&m_wallet, &wtx, mweb_coin->output_id);
            sub.credit = mweb_coin->amount;
            sub.involvesWatchAddress = ismine & ISMINE_WATCH_ONLY;
            sub.type = WalletTxRecord::Type::RecvWithAddress;
            StealthAddress addr;
            if (m_wallet.GetMWWallet()->GetStealthAddress(*mweb_coin, addr)) {
                sub.address = GenericAddress(addr).Encode();
            }
            tx_records.push_back(sub);
        }
    }

    for (const auto& [pegout_index, pegout] : wtx.GetMWEBPegouts()) {
        if (!(m_wallet.IsMine(GenericAddress{pegout.GetScriptPubKey()}) & filter_ismine)) {
            continue;
        }

        WalletTxRecord tx_record(&m_wallet, &wtx, pegout_index);
        tx_record.type = WalletTxRecord::Type::RecvWithAddress;
        tx_record.credit = pegout.GetAmount();
        tx_record.address = GenericAddress(pegout.GetScriptPubKey()).Encode();
        tx_records.push_back(std::move(tx_record));
    }
}

void TxList::List_Debit(std::vector<WalletTxRecord>& tx_records, const CWalletTx& wtx, const wallet::isminefilter& filter_ismine)
{
    CAmount nTxFee = (CachedTxIsFromMe(m_wallet, wtx, filter_ismine) ? CachedTxGetFee(m_wallet, wtx, filter_ismine) : 0);

    for (const AnyOutput& output : wtx.GetTxOutputs()) {
        // If the output is a peg-in script, and we have the MWEB pegin tx, then ignore the peg-in script output.
        // If it's a peg-in script, and we don't have the MWEB pegin tx, treat the output as a spend.
        mw::Hash kernel_id;
        if (!output.IsMWEB() && output.GetScriptPubKey().IsMWEBPegin(&kernel_id)) {
            if (wtx.tx->HasMWEBTx() && wtx.tx->mweb_tx.GetKernelIDs().count(kernel_id) > 0) {
                continue;
            }
        }

        if (m_wallet.IsMine(output)) {
            // Ignore parts sent to self, as this is usually the change
            // from a transaction sent back to our own address.
            continue;
        }

        WalletTxRecord tx_record(&m_wallet, &wtx, output.GetID());
        tx_record.debit = -m_wallet.GetValue(output);

        GenericAddress address = GetAddress(output);
        if (!address.IsEmpty()) {
            // Sent to Litecoin Address
            tx_record.type = WalletTxRecord::Type::SendToAddress;
            tx_record.address = address.Encode();
        } else {
            // Sent to IP, or other non-address transaction like OP_EVAL
            tx_record.type = WalletTxRecord::Type::SendToOther;
            tx_record.address = wtx.mapValue.count("to") > 0 ? wtx.mapValue.at("to") : "";
        }

        /* Add fee to first output */
        if (nTxFee > 0) {
            tx_record.fee = -nTxFee;
            nTxFee = 0;
        }

        tx_records.push_back(tx_record);
    }

    for (const auto& [pegout_index, pegout] : wtx.GetMWEBPegouts()) {
        if (m_wallet.IsMine(GenericAddress{pegout.GetScriptPubKey()})) {
            // Ignore parts sent to self, as this is usually the change
            // from a transaction sent back to our own address.
            continue;
        }

        WalletTxRecord tx_record(&m_wallet, &wtx, pegout_index);
        tx_record.debit = -pegout.GetAmount();
        tx_record.type = WalletTxRecord::Type::SendToAddress;
        tx_record.address = GenericAddress(pegout.GetScriptPubKey()).Encode();

        /* Add fee to first output */
        if (nTxFee > 0) {
            tx_record.fee = -nTxFee;
            nTxFee = 0;
        }

        tx_records.push_back(std::move(tx_record));
    }
}

void TxList::List_SelfSend(std::vector<WalletTxRecord>& tx_records, const CWalletTx& wtx, const wallet::isminefilter& filter_ismine)
{
    std::string address;
    for (const AnyOutput& output : wtx.GetTxOutputs()) {
        if (!output.IsMWEB() && output.GetScriptPubKey().IsMWEBPegin()) {
            continue;
        }

        if (!address.empty()) address += ", ";
        address += GetAddress(output).Encode();
    }

    for (const auto& pegout_entry : wtx.GetMWEBPegouts()) {
        const PegOutCoin& pegout = pegout_entry.second;
        if (!address.empty()) address += ", ";
        address += GenericAddress(pegout.GetScriptPubKey()).Encode();
    }

    CAmount nCredit = CachedTxGetCredit(m_wallet, wtx, filter_ismine);
    CAmount nDebit = CachedTxGetDebit(m_wallet, wtx, filter_ismine);
    CAmount nChange = CachedTxGetChange(m_wallet, wtx);

    WalletTxRecord tx_record(&m_wallet, &wtx);
    tx_record.type = WalletTxRecord::SendToSelf;
    tx_record.address = address;
    tx_record.debit = -(nDebit - nChange);
    tx_record.credit = nCredit - nChange;
    tx_records.push_back(std::move(tx_record));
}

wallet::isminetype TxList::IsAddressMine(const CWalletTx& wtx, const AnyOutput& txout)
{
    CTxDestination dest;
    return m_wallet.ExtractOutputDestination(wtx, txout.GetID(), dest) ? m_wallet.IsMine(dest) : ISMINE_NO;
}

GenericAddress TxList::GetAddress(const AnyOutput& output)
{
    if (!output.IsMWEB()) {
        return output.GetTxOut().scriptPubKey;
    }

    mw::WalletCoin coin;
    if (m_wallet.GetMWEBWalletCoin(output.ToMWEBOutputID(), coin)) {
        StealthAddress addr;
        if (m_wallet.GetMWWallet()->GetStealthAddress(coin, addr)) {
            return addr;
        }
    } else {
    }

    return GenericAddress{};
}

bool TxList::IsAllFromMe(const CWalletTx& wtx)
{
    for (const AnyInput& input : wtx.GetInputs()) {
        if (!InputIsMine(m_wallet, input)) {
            return false;
        }
    }

    return true;
}

bool TxList::IsAllToMe(const CWalletTx& wtx)
{
    for (const AnyOutput& output : wtx.GetTxOutputs()) {
        // If we don't have the MWEB peg-in tx, then we treat it as an output not belonging to ourselves.
        mw::Hash kernel_id;
        if (!output.IsMWEB() && output.GetScriptPubKey().IsMWEBPegin(&kernel_id)) {
            if (wtx.tx->HasMWEBTx() && wtx.tx->mweb_tx.GetKernelIDs().count(kernel_id) > 0) {
                continue;
            }
        }

        if (!m_wallet.IsMine(output)) {
            return false;
        }
    }

    // Also check pegouts
    for (const auto& pegout_entry : wtx.GetMWEBPegouts()) {
        const PegOutCoin& pegout = pegout_entry.second;
        if (!m_wallet.IsMine(GenericAddress{pegout.GetScriptPubKey()})) {
            return false;
        }
    }

    return true;
}

// A few release candidates of v0.21.2 added some transactions to the wallet that didn't actually belong to it.
// This is a temporary band-aid to filter out these transactions from the list.
// We can consider removing it after testing, since only a limited number of testnet wallets should've been impacted.
bool TxList::IsMine(const CWalletTx& wtx)
{
    for (const AnyInput& input : wtx.GetInputs()) {
        if (InputIsMine(m_wallet, input)) {
            return true;
        }
    }

    for (const AnyOutputID& output_id : wtx.GetOutputIDs(OutputIdMode::WALLET_OUTPUTS)) {
        if (m_wallet.IsMine(output_id)) {
            return true;
        }
    }

    for (const auto& pegout_entry : wtx.GetMWEBPegouts()) {
        const PegOutCoin& pegout = pegout_entry.second;
        if (m_wallet.IsMine(GenericAddress{pegout.GetScriptPubKey()})) {
            return true;
        }
    }

    return false;
}

} // namespace wallet
