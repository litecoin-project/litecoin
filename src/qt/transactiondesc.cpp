// Copyright (c) 2011-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifdef HAVE_CONFIG_H
#include <config/bitcoin-config.h>
#endif

#include <qt/transactiondesc.h>

#include <qt/bitcoinunits.h>
#include <qt/guiutil.h>
#include <qt/paymentserver.h>

#include <consensus/consensus.h>
#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <policy/policy.h>
#include <util/system.h>
#include <validation.h>
#include <wallet/ismine.h>
#include <wallet/txrecord.h>

#include <stdint.h>
#include <string>

#include <QLatin1String>

using wallet::ISMINE_ALL;
using wallet::ISMINE_SPENDABLE;
using wallet::ISMINE_WATCH_ONLY;
using wallet::isminetype;

/// Very lightweight HTML builder:
///  - wraps all your output in <html><font face=...> ... </font></html>
///  - callers pass translated labels so lupdate can extract strings at call sites
///  - AddMultiLine() puts an extra <br> before+after the value
///  - You can also set a custom font at any time
class HTMLBuilder
{
public:
    HTMLBuilder(const QString& font_face = "verdana, arial, helvetica, sans-serif")
    {
        m_html.reserve(4000);
        // default font - override with SetFont() if you like!
        m_html = "<html><font face='" + font_face + "'>";
    }

    /// Update to a new font.
    void SetFont(const QString& faceList)
    {
        m_html += "</font><font face='" + faceList + "'>";
    }

    void AddLine(const QString& line)
    {
        m_html += line + "<br>";
    }

    /// A single line:  <b>Key:</b> Value<br>
    void AddField(const QString& label, const QString& value)
    {
        m_html += "<b>" + label + ":</b> " + value + "<br>";
    }

    /// A single line:  <b>Key:</b> Value<br>
    void AddField(const QString& label, const std::string& value)
    {
        AddField(label, QString::fromStdString(value));
    }

    /// Like AddField(), but:
    ///   * puts a <br> before the value (so you can render multi-line messages nicely)
    ///   * still appends a <br> after
    void AddMultiLine(const QString& label, const QString& value)
    {
        m_html += "<br><b>" + label + ":</b><br>" + value + "<br>";
    }

    /// Like AddField(), but builds an unordered list (ul) for the value.
    void AddList(const QString& label, const QStringList& list)
    {
        m_html += "<br><b>" + label + ":</b><ul>";
        for (const QString& item : list) {
            m_html += "<li>" + item + "</li>";
        }
        m_html += "</ul><br>";
    }

    /// Raw HTML if you ever need it
    void AddRaw(const QString& htmlFragment)
    {
        m_html += htmlFragment;
    }

    /// Final output; closes the tags for you
    QString Str() const
    {
        return m_html + "</font></html>";
    }

private:
    QString m_html;
};


QString TransactionDesc::FormatTxStatus(const interfaces::WalletTxStatus& status, bool inMempool)
{
    int depth = status.depth_in_main_chain;
    if (depth < 0) {
        /*: Text explaining the current status of a transaction, shown in the
            status field of the details window for this transaction. This status
            represents an unconfirmed transaction that conflicts with a confirmed
            transaction. */
        return tr("conflicted with a transaction with %1 confirmations").arg(-depth);
    } else if (depth == 0) {
        QString s;
        if (inMempool) {
            /*: Text explaining the current status of a transaction, shown in the
                status field of the details window for this transaction. This status
                represents an unconfirmed transaction that is in the memory pool. */
            s = tr("0/unconfirmed, in memory pool");
        } else {
            /*: Text explaining the current status of a transaction, shown in the
                status field of the details window for this transaction. This status
                represents an unconfirmed transaction that is not in the memory pool. */
            s = tr("0/unconfirmed, not in memory pool");
        }
        if (status.is_abandoned) {
            /*: Text explaining the current status of a transaction, shown in the
                status field of the details window for this transaction. This
                status represents an abandoned transaction. */
            s += QLatin1String(", ") + tr("abandoned");
        }
        return s;
    } else if (depth < 6) {
        /*: Text explaining the current status of a transaction, shown in the
            status field of the details window for this transaction. This
            status represents a transaction confirmed in at least one block,
            but less than 6 blocks. */
        return tr("%1/unconfirmed").arg(depth);
    } else {
        /*: Text explaining the current status of a transaction, shown in the
            status field of the details window for this transaction. This status
            represents a transaction confirmed in 6 or more blocks. */
        return tr("%1 confirmations").arg(depth);
    }
}

// Takes an encoded PaymentRequest as a string and tries to find the Common Name of the X.509 certificate
// used to sign the PaymentRequest.
bool GetPaymentRequestMerchant(const std::string& pr, QString& merchant)
{
    // Search for the supported pki type strings
    if (pr.find(std::string({0x12, 0x0b}) + "x509+sha256") != std::string::npos || pr.find(std::string({0x12, 0x09}) + "x509+sha1") != std::string::npos) {
        // We want the common name of the Subject of the cert. This should be the second occurrence
        // of the bytes 0x0603550403. The first occurrence of those is the common name of the issuer.
        // After those bytes will be either 0x13 or 0x0C, then length, then either the ascii or utf8
        // string with the common name which is the merchant name
        const std::string cn_oid{"\x06\x03\x55\x04\x03", 5};
        size_t cn_pos = pr.find(cn_oid);
        if (cn_pos != std::string::npos) {
            cn_pos = pr.find(cn_oid, cn_pos + cn_oid.size());
            if (cn_pos != std::string::npos) {
                cn_pos += cn_oid.size();
                if (cn_pos < pr.size() && (pr[cn_pos] == 0x13 || pr[cn_pos] == 0x0c)) {
                    cn_pos++; // Consume the type
                    if (cn_pos >= pr.size()) {
                        return false;
                    }
                    const auto str_len = static_cast<unsigned char>(pr[cn_pos]);
                    cn_pos++; // Consume the string length
                    if ((str_len & 0x80) != 0 || str_len > pr.size() - cn_pos) {
                        return false;
                    }
                    merchant = QString::fromUtf8(pr.data() + cn_pos, str_len);
                    return true;
                }
            }
        }
    }
    return false;
}

QString TransactionDesc::toHTML(interfaces::Node& node, interfaces::Wallet& wallet, wallet::WalletTxRecord* rec, BitcoinUnit unit)
{
    interfaces::WalletTxStatus status;
    interfaces::WalletOrderForm orderForm;
    bool inMempool;
    int numBlocks;
    interfaces::WalletTx wtx = wallet.getWalletTxDetails(rec->GetTxHash(), status, orderForm, inMempool, numBlocks);

    HTMLBuilder html;
    html.AddField(tr("Status"), FormatTxStatus(status, inMempool));
    html.AddField(tr("Date"), wtx.time ? GUIUtil::dateTimeStr(wtx.time) : QString());

    html.AddRaw(toHTML_Addresses(wallet, wtx, rec));
    html.AddRaw(toHTML_Amounts(wallet, wtx, status, unit));

    //
    // Message
    //
    if (wtx.value_map.count("message") && !wtx.value_map["message"].empty())
        html.AddMultiLine(tr("Message"), GUIUtil::HtmlEscape(wtx.value_map["message"], true));
    if (wtx.value_map.count("comment") && !wtx.value_map["comment"].empty())
        html.AddMultiLine(tr("Comment"), GUIUtil::HtmlEscape(wtx.value_map["comment"], true));

    html.AddField(tr("Transaction ID"), rec->GetTxHash().ToString());
    html.AddField(tr("Transaction total size"), QString::number(wtx.tx->GetTotalSize()) + " bytes");
    html.AddField(tr("Transaction virtual size"), QString::number(GetVirtualTransactionSize(*wtx.tx)) + " bytes");
    if (wtx.tx->HasMWEBTx()) {
        html.AddField(tr("Transaction MWEB weight"), QString::number(wtx.tx->mweb_tx.GetMWEBWeight()));
    }

    html.AddField(tr("Component index"), rec->GetComponentIndex());

    html.AddRaw(toHTML_OrderForm(orderForm));

    if (wtx.is_coinbase) {
        quint32 numBlocksToMaturity = COINBASE_MATURITY + 1;
        html.AddLine(tr("Generated coins must mature %1 blocks before they can be spent. When you generated this block, it was broadcast to the network to be added to the block chain. If it fails to get into the chain, its state will change to \"not accepted\" and it won't be spendable. This may occasionally happen if another node generates a block within a few seconds of yours.").arg(QString::number(numBlocksToMaturity)));
    }
    if (wtx.is_hogex || !wtx.pegouts.empty()) {
        quint32 numBlocksToMaturity = PEGOUT_MATURITY + 1;
        html.AddLine(tr("Pegout outputs must mature %1 blocks before they can be spent. When this pegout is mined, it is included in the HogEx transaction for the block. If the block fails to remain in the chain, its state will change to \"not accepted\" and the pegout won't be spendable.").arg(QString::number(numBlocksToMaturity)));
    }

    //
    // Debug view
    //
    if (node.getLogCategories() != BCLog::NONE) {
        html.AddRaw(toHTML_Debug(node, wallet, wtx, rec, unit));
    }

    return html.Str();
}

QString TransactionDesc::toHTML_Addresses(interfaces::Wallet& wallet, const interfaces::WalletTx& wtx, wallet::WalletTxRecord* rec)
{
    QString strHTML;

    //
    // From
    //
    if (wtx.is_coinbase) {
        strHTML += "<b>" + tr("Source") + ":</b> " + tr("Generated") + "<br>";
    } else if (wtx.value_map.count("from") && !wtx.value_map.at("from").empty()) {
        // Online transaction
        strHTML += "<b>" + tr("From") + ":</b> " + GUIUtil::HtmlEscape(wtx.value_map.at("from")) + "<br>";
    } else {
        // Offline transaction
        if (wtx.credit > wtx.debit) {
            // Credit
            CTxDestination address = DecodeDestination(rec->address);
            if (IsValidDestination(address)) {
                std::string name;
                isminetype ismine;
                if (wallet.getAddress(address, &name, &ismine, /* purpose= */ nullptr)) {
                    strHTML += "<b>" + tr("From") + ":</b> " + tr("unknown") + "<br>";
                    strHTML += "<b>" + tr("To") + ":</b> ";
                    strHTML += GUIUtil::HtmlEscape(rec->address);
                    QString addressOwned = ismine == ISMINE_SPENDABLE ? tr("own address") : tr("watch-only");
                    if (!name.empty())
                        strHTML += " (" + addressOwned + ", " + tr("label") + ": " + GUIUtil::HtmlEscape(name) + ")";
                    else
                        strHTML += " (" + addressOwned + ")";
                    strHTML += "<br>";
                }
            }
        }
    }

    //
    // To
    //
    if (wtx.value_map.count("to") && !wtx.value_map.at("to").empty()) {
        std::string to_address = wtx.value_map.at("to");

        // Online transaction
        QString label = "";
        CTxDestination dest = DecodeDestination(to_address);
        if (IsValidDestination(dest)) {
            std::string name;
            if (wallet.getAddress(dest, &name, /* is_mine= */ nullptr, /* purpose= */ nullptr) && !name.empty()) {
                label = GUIUtil::HtmlEscape(name) + " ";
            }
        }

        strHTML += "<b>" + tr("To") + ":</b> " + label + GUIUtil::HtmlEscape(to_address) + "<br>";
    }

    return strHTML;
}

QString TransactionDesc::toHTML_Amounts(interfaces::Wallet& wallet, const interfaces::WalletTx& wtx, const interfaces::WalletTxStatus& status, BitcoinUnit unit)
{
    QString strHTML;
    CAmount nNet = wtx.credit - wtx.debit;

    //
    // Amount
    //
    if (status.blocks_to_maturity > 0 && wtx.credit == 0) // Blocks to maturity covers coinbase and pegouts (HogEx)
    {
        //
        // Coinbase & Pegouts (HogEx)
        //
        CAmount nUnmatured = 0;
        for (const interfaces::WalletTxOut& wtxout : wtx.outputs) {
            if ((wtxout.is_mine & ISMINE_ALL) != wallet::isminetype::ISMINE_NO) {
                nUnmatured += wtxout.nValue;
            }
        }
        strHTML += "<b>" + tr("Credit") + ":</b> ";
        if (status.is_in_main_chain)
            strHTML += BitcoinUnits::formatHtmlWithUnit(unit, nUnmatured) + " (" + tr("matures in %n more block(s)", "", status.blocks_to_maturity) + ")";
        else
            strHTML += "(" + tr("not accepted") + ")";
        strHTML += "<br>";
    } else if (nNet > 0) {
        //
        // Credit
        //
        strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, nNet) + "<br>";
    } else {
        isminetype fAllFromMe = ISMINE_SPENDABLE;
        for (const auto& wtxin : wtx.inputs) {
            if (fAllFromMe > wtxin.is_mine) fAllFromMe = wtxin.is_mine;
        }

        isminetype fAllToMe = ISMINE_SPENDABLE;
        for (const auto& wtxout : wtx.outputs) {
            if (fAllToMe > wtxout.is_mine) fAllToMe = wtxout.is_mine;
        }

        for (const auto& wtx_pegout : wtx.pegouts) {
            if (fAllToMe > wtx_pegout.is_mine) fAllToMe = wtx_pegout.is_mine;
        }

        if (fAllFromMe) {
            if (fAllFromMe & ISMINE_WATCH_ONLY)
                strHTML += "<b>" + tr("From") + ":</b> " + tr("watch-only") + "<br>";

            //
            // Debit
            //
            for (const interfaces::WalletTxOut& wtxout : wtx.outputs) {
                // Ignore change
                isminetype toSelf = wtxout.is_mine;
                if ((toSelf == ISMINE_SPENDABLE) && (fAllFromMe == ISMINE_SPENDABLE))
                    continue;

                if (!wtx.value_map.count("to") || wtx.value_map.at("to").empty()) {
                    // Offline transaction
                    CTxDestination dest;
                    if (wtxout.address.ExtractDestination(dest)) {
                        strHTML += "<b>" + tr("To") + ":</b> ";
                        std::string name;
                        if (wallet.getAddress(dest, &name, /* is_mine= */ nullptr, /* purpose= */ nullptr) && !name.empty()) {
                            strHTML += GUIUtil::HtmlEscape(name) + " ";
                        }
                        strHTML += GUIUtil::HtmlEscape(wtxout.address.Encode());
                        if (toSelf == ISMINE_SPENDABLE) {
                            strHTML += " (own address)";
                        } else if (toSelf & ISMINE_WATCH_ONLY) {
                            strHTML += " (watch-only)";
                        }
                        strHTML += "<br>";
                    }
                }

                strHTML += "<b>" + tr("Debit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -wtxout.nValue) + "<br>";
                if (toSelf) {
                    strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, wtxout.nValue) + "<br>";
                }
            }

            for (const interfaces::WalletTxPegOut& wtx_pegout : wtx.pegouts) {
                if ((wtx_pegout.is_mine == ISMINE_SPENDABLE) && (fAllFromMe == ISMINE_SPENDABLE))
                    continue;

                CTxDestination dest;
                if (::ExtractDestination(wtx_pegout.pegout.GetScriptPubKey(), dest)) {
                    strHTML += "<b>" + tr("To") + ":</b> ";
                    std::string name;
                    if (wallet.getAddress(dest, &name, /* is_mine= */ nullptr, /* purpose= */ nullptr) && !name.empty()) {
                        strHTML += GUIUtil::HtmlEscape(name) + " ";
                    }

                    strHTML += GUIUtil::HtmlEscape(::EncodeDestination(dest));
                    if (wtx_pegout.is_mine == ISMINE_SPENDABLE)
                        strHTML += " (own address)";
                    else if (wtx_pegout.is_mine & ISMINE_WATCH_ONLY)
                        strHTML += " (watch-only)";
                    strHTML += "<br>";
                }

                strHTML += "<b>" + tr("Debit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -wtx_pegout.pegout.GetAmount()) + "<br>";
                if (wtx_pegout.is_mine)
                    strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, wtx_pegout.pegout.GetAmount()) + "<br>";
            }

            if (fAllToMe) {
                // Payment to self
                CAmount nValue = wtx.credit - wtx.change;
                strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, wtx.credit) + "<br>";
                strHTML += "<b>" + tr("Change") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, wtx.change) + "<br>";
                strHTML += "<b>" + tr("Total debit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -nValue) + "<br>";
                strHTML += "<b>" + tr("Total credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, nValue) + "<br>";
            }

            CAmount nTxFee = wtx.fee;
            if (nTxFee > 0)
                strHTML += "<b>" + tr("Transaction fee") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -nTxFee) + "<br>";
        } else {
            //
            // Mixed debit transaction
            //
            for (const interfaces::WalletTxIn& wtxin : wtx.inputs) {
                if (wtxin.is_mine) {
                    strHTML += "<b>" + tr("Debit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -wtxin.nDebit) + "<br>";
                }
            }

            for (const interfaces::WalletTxOut& wtxout : wtx.outputs) {
                if (wtxout.is_mine) {
                    strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, wtxout.nValue) + "<br>";
                }
            }

            for (const interfaces::WalletTxPegOut& wtx_pegout : wtx.pegouts) {
                if (wtx_pegout.is_mine) {
                    strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, wtx_pegout.pegout.GetAmount()) + "<br>";
                }
            }
        }
    }

    strHTML += "<b>" + tr("Net amount") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, nNet, true) + "<br>";
    return strHTML;
}

QString TransactionDesc::toHTML_OrderForm(const interfaces::WalletOrderForm& orderForm)
{
    QString strHTML;

    // Message from normal litecoin:URI (litecoin:123...?message=example)
    for (const std::pair<std::string, std::string>& r : orderForm) {
        if (r.first == "Message")
            strHTML += "<br><b>" + tr("Message") + ":</b><br>" + GUIUtil::HtmlEscape(r.second, true) + "<br>";

        //
        // PaymentRequest info:
        //
        if (r.first == "PaymentRequest") {
            QString merchant;
            if (!GetPaymentRequestMerchant(r.second, merchant)) {
                merchant.clear();
            } else {
                merchant += tr(" (Certificate was not verified)");
            }
            if (!merchant.isNull()) {
                strHTML += "<b>" + tr("Merchant") + ":</b> " + GUIUtil::HtmlEscape(merchant) + "<br>";
            }
        }
    }

    return strHTML;
}

QString TransactionDesc::toHTML_Debug(interfaces::Node& node, interfaces::Wallet& wallet, const interfaces::WalletTx& wtx, wallet::WalletTxRecord* rec, BitcoinUnit unit)
{
    QString strHTML = "<hr><br>" + tr("Debug information") + "<br><br>";
    for (const interfaces::WalletTxIn& wtxin : wtx.inputs) {
        if (wtxin.is_mine) {
            strHTML += "<b>" + tr("Debit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -wtxin.nDebit) + "<br>";
        }
    }
    for (const interfaces::WalletTxOut& wtxout : wtx.outputs) {
        if (wtxout.is_mine) {
            strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, wtxout.nValue) + "<br>";
        }
    }

    strHTML += "<br><b>" + tr("Transaction") + ":</b><br>";
    strHTML += GUIUtil::HtmlEscape(wtx.tx->ToString(), true);

    strHTML += "<br><b>" + tr("Inputs") + ":</b>";
    strHTML += "<ul>";

    for (const interfaces::WalletTxIn& wtxin : wtx.inputs) {
        strHTML += "<li>";

        AnyOutput prevout;
        if (node.getUnspentOutput(wtxin.input.GetID(), prevout)) {
            CTxDestination address;
            if (wallet.extractOutputDestination(prevout, address)) {
                std::string name;
                if (wallet.getAddress(address, &name, /* is_mine= */ nullptr, /* purpose= */ nullptr) && !name.empty()) {
                    strHTML += GUIUtil::HtmlEscape(name) + " ";
                }
                strHTML += QString::fromStdString(EncodeDestination(address));
            }

            strHTML = strHTML + " " + tr("Amount") + "=" + BitcoinUnits::formatHtmlWithUnit(unit, wallet.getValue(prevout));
        }

        strHTML = strHTML + " IsMine=" + (wtxin.is_mine & ISMINE_SPENDABLE ? tr("true") : tr("false"));
        strHTML = strHTML + " IsWatchOnly=" + (wtxin.is_mine & ISMINE_WATCH_ONLY ? tr("true") : tr("false"));
        strHTML += "</li>";
    }

    strHTML += "</ul>";


    strHTML += "<br><b>" + tr("Outputs") + ":</b>";
    strHTML += "<ul>";

    for (const interfaces::WalletTxOut& wtxout : wtx.outputs) {
        strHTML += "<li>";

        CTxDestination destination;
        if (wtxout.address.ExtractDestination(destination)) {
            std::string name;
            if (wallet.getAddress(destination, &name, /* is_mine= */ nullptr, /* purpose= */ nullptr) && !name.empty()) {
                strHTML += GUIUtil::HtmlEscape(name) + " ";
            }
            strHTML += QString::fromStdString(EncodeDestination(destination));
        }

        strHTML = strHTML + " " + tr("Amount") + "=" + BitcoinUnits::formatHtmlWithUnit(unit, wtxout.nValue);

        strHTML = strHTML + " IsMine=" + (wtxout.is_mine & ISMINE_SPENDABLE ? tr("true") : tr("false"));
        strHTML = strHTML + " IsWatchOnly=" + (wtxout.is_mine & ISMINE_WATCH_ONLY ? tr("true") : tr("false"));
        strHTML += "</li>";
    }

    strHTML += "</ul>";

    return strHTML;
}
