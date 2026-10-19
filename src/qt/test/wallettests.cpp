// Copyright (c) 2015-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/wallettests.h>
#include <qt/test/util.h>

#include <interfaces/chain.h>
#include <interfaces/node.h>
#include <key_io.h>
#include <mweb/mweb_wallet.h>
#include <qt/bitcoinamountfield.h>
#include <qt/bitcoinunits.h>
#include <qt/clientmodel.h>
#include <qt/coincontroldialog.h>
#include <qt/optionsmodel.h>
#include <qt/overviewpage.h>
#include <qt/platformstyle.h>
#include <qt/psbtoperationsdialog.h>
#include <qt/qvalidatedlineedit.h>
#include <qt/receivecoinsdialog.h>
#include <qt/receiverequestdialog.h>
#include <qt/recentrequeststablemodel.h>
#include <qt/sendcoinsdialog.h>
#include <qt/sendcoinsentry.h>
#include <qt/transactiontablemodel.h>
#include <qt/transactionview.h>
#include <qt/walletmodel.h>
#include <qt/walletmodeltransaction.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <chrono>
#include <memory>
#include <utility>
#include <vector>

#include <QAbstractButton>
#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QLineEdit>
#include <QPushButton>
#include <QRadioButton>
#include <QTemporaryDir>
#include <QTimer>
#include <QVBoxLayout>
#include <QTextEdit>
#include <QTreeWidget>
#include <QListView>
#include <QDialogButtonBox>

using wallet::AddWallet;
using wallet::CWallet;
using wallet::CreateMockWalletDatabase;
using wallet::RemoveWallet;
using wallet::WALLET_FLAG_DESCRIPTORS;
using wallet::WalletContext;
using wallet::WalletDescriptor;
using wallet::WalletRescanReserver;

namespace
{
//! Press "Yes" or "Cancel" buttons in modal send confirmation dialog.
void ConfirmSend(QString* text = nullptr, bool cancel = false)
{
    QTimer::singleShot(0, [text, cancel]() {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (widget->inherits("SendConfirmationDialog")) {
                SendConfirmationDialog* dialog = qobject_cast<SendConfirmationDialog*>(widget);
                if (text) *text = dialog->text();
                QAbstractButton* button = dialog->button(cancel ? QMessageBox::Cancel : QMessageBox::Yes);
                button->setEnabled(true);
                button->click();
            }
        }
    });
}

//! Send coins to address and return txid.
uint256 SendCoins(CWallet& wallet, SendCoinsDialog& sendCoinsDialog, const CTxDestination& address, CAmount amount, bool rbf)
{
    QVBoxLayout* entries = sendCoinsDialog.findChild<QVBoxLayout*>("entries");
    SendCoinsEntry* entry = qobject_cast<SendCoinsEntry*>(entries->itemAt(0)->widget());
    entry->findChild<QValidatedLineEdit*>("payTo")->setText(QString::fromStdString(EncodeDestination(address)));
    entry->findChild<BitcoinAmountField*>("payAmount")->setValue(amount);
    // Litecoin: Disable RBF
    // sendCoinsDialog.findChild<QFrame*>("frameFee")
    //     ->findChild<QFrame*>("frameFeeSelection")
    //     ->findChild<QCheckBox*>("optInRBF")
    //     ->setCheckState(rbf ? Qt::Checked : Qt::Unchecked);
    uint256 txid;
    boost::signals2::scoped_connection c(wallet.NotifyTransactionChanged.connect([&txid](const uint256& hash, ChangeType status) {
        if (status == CT_NEW) txid = hash;
    }));
    ConfirmSend();
    bool invoked = QMetaObject::invokeMethod(&sendCoinsDialog, "sendButtonClicked", Q_ARG(bool, false));
    assert(invoked);
    return txid;
}

//! Find index of txid in transaction list.
QModelIndex FindTx(const QAbstractItemModel& model, const uint256& txid)
{
    QString hash = QString::fromStdString(txid.ToString());
    int rows = model.rowCount({});
    for (int row = 0; row < rows; ++row) {
        QModelIndex index = model.index(row, 0, {});
        if (model.data(index, TransactionTableModel::TxHashRole) == hash) {
            return index;
        }
    }
    return {};
}

// Litecoin: Disable RBF
////! Invoke bumpfee on txid and check results.
//void BumpFee(TransactionView& view, const uint256& txid, bool expectDisabled, std::string expectError, bool cancel)
//{
//    QTableView* table = view.findChild<QTableView*>("transactionView");
//    QModelIndex index = FindTx(*table->selectionModel()->model(), txid);
//    QVERIFY2(index.isValid(), "Could not find BumpFee txid");
//
//    // Select row in table, invoke context menu, and make sure bumpfee action is
//    // enabled or disabled as expected.
//    QAction* action = view.findChild<QAction*>("bumpFeeAction");
//    table->selectionModel()->select(index, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
//    action->setEnabled(expectDisabled);
//    table->customContextMenuRequested({});
//    QCOMPARE(action->isEnabled(), !expectDisabled);
//
//    action->setEnabled(true);
//    QString text;
//    if (expectError.empty()) {
//        ConfirmSend(&text, cancel);
//    } else {
//        ConfirmMessage(&text, 0ms);
//    }
//    action->trigger();
//    QVERIFY(text.indexOf(QString::fromStdString(expectError)) != -1);
//}

void CompareBalance(WalletModel& walletModel, CAmount expected_balance, QLabel* balance_label_to_check)
{
    BitcoinUnit unit = walletModel.getOptionsModel()->getDisplayUnit();
    QString balanceComparison = BitcoinUnits::formatWithUnit(unit, expected_balance, false, BitcoinUnits::SeparatorStyle::ALWAYS);
    QCOMPARE(balance_label_to_check->text().trimmed(), balanceComparison);
}

// Fee subtraction must preserve each GUI recipient's amount across output layers, sorting and change.
void TestSendCoinsRecipientAmounts(WalletModel& wallet_model, CWallet& wallet)
{
    const auto make_recipient = [](const CTxDestination& destination, CAmount amount) {
        SendCoinsRecipient recipient;
        recipient.address = QString::fromStdString(EncodeDestination(destination));
        recipient.amount = amount;
        return recipient;
    };
    CKey key1, key2, change_key;
    key1.MakeNewKey(true);
    key2.MakeNewKey(true);
    change_key.MakeNewKey(true);
    const auto mweb1 = make_recipient(StealthAddress::Random(), COIN);
    const auto mweb2 = make_recipient(StealthAddress::Random(), 2 * COIN);
    const auto ltc1 = make_recipient(PKHash(key1.GetPubKey()), 3 * COIN);
    const auto ltc2 = make_recipient(PKHash(key2.GetPubKey()), 4 * COIN);

    for (const QList<SendCoinsRecipient>& original : {
             QList<SendCoinsRecipient>{mweb1, ltc1, mweb2, ltc2},
             QList<SendCoinsRecipient>{ltc2, mweb2, ltc1, mweb1},
             QList<SendCoinsRecipient>{mweb1, mweb2},
             QList<SendCoinsRecipient>{ltc1, ltc2}}) {
        const bool has_mweb_recipient = std::any_of(original.begin(), original.end(), [](const SendCoinsRecipient& recipient) {
            return std::holds_alternative<StealthAddress>(DecodeDestination(recipient.address.toStdString()));
        });
        for (bool custom_change : {false, true}) {
            wallet::CCoinControl coin_control;
            coin_control.m_feerate = CFeeRate{10000};
            if (custom_change) {
                // Force peg-outs, including a change peg-out when MWEB recipients are present.
                coin_control.destChange = has_mweb_recipient
                    ? CTxDestination{PKHash(change_key.GetPubKey())}
                    : CTxDestination{StealthAddress::Random()};
            }
            for (int subtract_count : {0, 1, original.size()}) {
                QList<SendCoinsRecipient> recipients = original;
                for (int i = 0; i < subtract_count; ++i) recipients[i].fSubtractFeeFromAmount = true;
                WalletModelTransaction transaction(recipients);
                QCOMPARE(wallet_model.prepareTransaction(transaction, coin_control).status, WalletModel::OK);
                QVERIFY(transaction.getWtx());
                const CTransaction& tx = *transaction.getWtx();
                const auto displayed = transaction.getRecipients();
                QCOMPARE(displayed.size(), recipients.size());
                // Read signed-output metadata after preparation, as commit would persist it.
                // Confirmation must already be correct before these coins enter the wallet.
                QVERIFY(WITH_LOCK(wallet.cs_wallet, return wallet.GetMWWallet()->SaveStagedCoinsToWallet(tx.mweb_tx.GetOutputIDs())));

                CAmount original_total{0};
                for (int i = 0; i < recipients.size(); ++i) {
                    const GenericAddress destination{DecodeDestination(recipients[i].address.toStdString())};
                    std::optional<CAmount> actual_amount;
                    for (const AnyOutput& output : tx.GetOutputs()) {
                        if (output.IsMWEB()) {
                            mw::WalletCoin coin;
                            QVERIFY(WITH_LOCK(wallet.cs_wallet, return wallet.GetMWEBWalletCoin(output.ToMWEBOutputID(), coin)));
                            if (coin.address && GenericAddress{*coin.address} == destination) actual_amount = coin.amount;
                        } else if (GenericAddress{output.GetScriptPubKey()} == destination) {
                            actual_amount = output.GetTxOut().nValue;
                        }
                    }
                    for (const PegOutCoin& pegout : tx.mweb_tx.GetPegOuts()) {
                        if (GenericAddress{pegout.GetScriptPubKey()} == destination) actual_amount = pegout.GetAmount();
                    }
                    QVERIFY(actual_amount.has_value());
                    QCOMPARE(displayed[i].address, recipients[i].address);
                    QCOMPARE(displayed[i].amount, *actual_amount);
                    if (!recipients[i].fSubtractFeeFromAmount) QCOMPARE(displayed[i].amount, recipients[i].amount);
                    original_total += recipients[i].amount;
                }
                QCOMPARE(transaction.getTotalTransactionAmount(),
                    original_total - (subtract_count ? transaction.getTransactionFee() : 0));
            }
        }
    }
}

// MWEB checkboxes must record exact inputs, fund pegouts, and support deselection and group selection.
void TestMWEBCoinControl(WalletModel& wallet_model, CWallet& wallet, const PlatformStyle* platform_style)
{
    const auto destination = wallet.GetNewDestination(OutputType::MWEB, "");
    QVERIFY(destination);
    const StealthAddress address = std::get<StealthAddress>(*destination);
    const auto* spk_man = dynamic_cast<wallet::DescriptorScriptPubKeyMan*>(wallet.GetScriptPubKeyMan(OutputType::MWEB, false));
    QVERIFY(spk_man);
    const auto address_index = spk_man->GetMWEBAddressIndex(address);
    QVERIFY(address_index);
    const mw::Hash selected_id = mw::Hash::ValueOf(101);
    const mw::Hash other_id = mw::Hash::ValueOf(102);
    {
        LOCK(wallet.cs_wallet);
        for (const auto& output_id : {selected_id, other_id}) {
            mw::WalletCoin coin;
            coin.output_id = output_id;
            coin.amount = output_id == selected_id ? 2 * COIN : 3 * COIN;
            coin.address = address;
            coin.address_index = *address_index;
            QVERIFY(wallet.GetMWWallet()->SaveToWallet({coin}));
            QVERIFY(wallet.AddToWallet(MakeTransactionRef(), MWEB::WalletTxInfo::Received(output_id),
                wallet::TxStateConfirmed{wallet.GetLastBlockHash(), wallet.GetLastBlockHeight(), 0}));
        }
        wallet.MarkDirty();
    }

    CKey recipient_key;
    recipient_key.MakeNewKey(true);
    const CScript recipient_script = GetScriptForDestination(WitnessV0KeyHash(recipient_key.GetPubKey()));
    const std::vector<wallet::CRecipient> recipients{{recipient_script, COIN, false}};
    wallet::CCoinControl coin_control;
    coin_control.m_feerate = CFeeRate{1000};
    coin_control.fOverrideFeeRate = true;
    const auto build = [&](CAmount amount) {
        auto send = recipients;
        send.front().nAmount = amount;
        return wallet::CreateTransaction(wallet, send, -1, coin_control, std::nullopt, std::nullopt, false);
    };

    const auto automatic = build(COIN);
    QVERIFY2(automatic, util::ErrorString(automatic).original.c_str());
    QVERIFY(!automatic->tx.vin.empty());
    QVERIFY(automatic->tx.mweb_tx.inputs.empty());

    CoinControlDialog dialog(coin_control, &wallet_model, platform_style);
    auto* tree = dialog.findChild<QTreeWidget*>("treeWidget");
    QVERIFY(tree);
    for (bool tree_mode : {false, true}) {
        dialog.findChild<QRadioButton*>(tree_mode ? "radioTreeMode" : "radioListMode")->click();
        QTreeWidgetItem* selected_item{nullptr};
        QTreeWidgetItemIterator it(tree);
        for (; *it; ++it) {
            if ((*it)->childCount() == 0 && (*it)->data(1, Qt::UserRole).toLongLong() == 2 * COIN) {
                selected_item = *it;
            }
        }
        QVERIFY(selected_item);
        selected_item->setCheckState(0, Qt::Checked);
        QVERIFY(coin_control.IsSelected(selected_id));
        std::vector<AnyOutputID> selected;
        coin_control.ListSelected(selected);
        QCOMPARE(selected.size(), size_t{1});
        QCOMPARE(dialog.findChild<QLabel*>("labelCoinControlQuantity")->text(), QString{"1"});

        const auto pegout = build(COIN);
        QVERIFY2(pegout, util::ErrorString(pegout).original.c_str());
        QVERIFY(pegout->tx.vin.empty());
        QCOMPARE(pegout->tx.mweb_tx.inputs.size(), size_t{1});
        QVERIFY(pegout->tx.mweb_tx.inputs.front().output_id == selected_id);
        QCOMPARE(pegout->tx.mweb_tx.GetPegOutCoins().size(), size_t{1});
        const auto insufficient = build(3 * COIN);
        QVERIFY(!insufficient);
        QCOMPARE(util::ErrorString(insufficient).original, std::string{"Insufficient funds"});

        selected_item->setCheckState(0, Qt::Unchecked);
        QVERIFY(!coin_control.HasSelected());
        if (tree_mode) {
            auto* parent = selected_item->parent();
            QVERIFY(parent);
            parent->setCheckState(0, Qt::Checked);
            QVERIFY(coin_control.IsSelected(selected_id));
            QVERIFY(coin_control.IsSelected(other_id));
            coin_control.ListSelected(selected);
            QCOMPARE(selected.size(), size_t{2});
            parent->setCheckState(0, Qt::Unchecked);
            QVERIFY(!coin_control.HasSelected());
        }

        auto* select_all = dialog.findChild<QPushButton*>("pushButtonSelectAll");
        QVERIFY(select_all);
        select_all->click();
        QVERIFY(coin_control.IsSelected(selected_id));
        QVERIFY(coin_control.IsSelected(other_id));
        select_all->click();
        QVERIFY(!coin_control.HasSelected());
    }
}

// Payment requests must preserve both address types, allow multiple recipients, and subtract fees when using the balance.
void TestSendCoinsAddressEntry(WalletModel& wallet_model, const PlatformStyle* platform_style)
{
    SendCoinsDialog dialog(platform_style);
    dialog.setModel(&wallet_model);
    CKey key;
    key.MakeNewKey(true);
    const QList<SendCoinsRecipient> recipients{
        SendCoinsRecipient{QString::fromStdString(EncodeDestination(StealthAddress::Random())), "MWEB", COIN, "MWEB payment"},
        SendCoinsRecipient{QString::fromStdString(EncodeDestination(WitnessV0KeyHash(key.GetPubKey()))), "LTC", 2 * COIN, "LTC payment"},
    };
    auto* entries = dialog.findChild<QVBoxLayout*>("entries");
    QVERIFY(entries);
    for (const SendCoinsRecipient& recipient : recipients) {
        QVERIFY(dialog.handlePaymentRequest(recipient));
    }
    QCOMPARE(entries->count(), recipients.size());
    for (int i = 0; i < recipients.size(); ++i) {
        auto* entry = qobject_cast<SendCoinsEntry*>(entries->itemAt(i)->widget());
        QVERIFY(entry);
        QVERIFY(entry->validate(wallet_model.node()));
        const auto value = entry->getValue();
        QCOMPARE(value.address, recipients[i].address);
        QCOMPARE(value.amount, recipients[i].amount);
        QCOMPARE(value.label, recipients[i].label);
        QCOMPARE(value.message, recipients[i].message);
    }

    dialog.clear();
    QCOMPARE(entries->count(), 1);
    QVERIFY(dialog.handlePaymentRequest(recipients.front()));
    auto* entry = qobject_cast<SendCoinsEntry*>(entries->itemAt(0)->widget());
    QVERIFY(entry);
    entry->findChild<QCheckBox*>("checkboxSubtractFeeFromAmount")->setChecked(false);
    auto* use_balance = entry->findChild<QPushButton*>("useAvailableBalanceButton");
    QVERIFY(use_balance);
    use_balance->click();
    const auto value = entry->getValue();
    QCOMPARE(value.address, recipients.front().address);
    QCOMPARE(value.amount, wallet_model.getAvailableBalance(nullptr));
    QVERIFY(value.fSubtractFeeFromAmount);
}

// PSBT review and saving must include transparent/MWEB outputs and every kernel pegout in both supported versions.
void TestPSBTOperations(ClientModel& client_model)
{
    CKey key;
    key.MakeNewKey(true);
    const CTxDestination address = WitnessV0KeyHash(key.GetPubKey());
    const CTxDestination mweb_address = StealthAddress::Random();
    const CScript script = GetScriptForDestination(address);
    const CAmount fee{10000};
    const BitcoinUnit unit = client_model.getOptionsModel()->getDisplayUnit();

    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint(uint256::ONE, 0));
    tx.vout.emplace_back(COIN, script);
    PartiallySignedTransaction canonical_v0(tx, 0);
    canonical_v0.inputs[0].witness_utxo = CTxOut(COIN + fee, script);
    PartiallySignedTransaction canonical_v2(tx, 2);
    canonical_v2.inputs[0].witness_utxo = canonical_v0.inputs[0].witness_utxo;

    PartiallySignedTransaction mweb;
    mweb.m_psbt_version = 2;
    mweb.tx_version = 2;
    mweb.inputs.emplace_back(2);
    mweb.inputs[0].mweb_output_id = mw::Hash::ValueOf(1);
    mweb.inputs[0].mweb_amount = 2 * COIN + fee;
    mweb.outputs.emplace_back(2);
    mweb.outputs[0].amount = 2 * COIN;
    mweb.outputs[0].mweb_stealth_address = std::get<StealthAddress>(mweb_address);
    mweb.kernels.emplace_back();
    mweb.kernels[0].features = mw::Kernel::FEE_FEATURE_BIT;
    mweb.kernels[0].fee = fee;

    PartiallySignedTransaction pegin = canonical_v2;
    pegin.inputs[0].witness_utxo.nValue = 2 * COIN + fee;
    pegin.outputs[0].amount = 2 * COIN + fee;
    pegin.outputs[0].script = GetScriptForPegin(mw::Hash{});
    pegin.outputs.push_back(mweb.outputs[0]);
    pegin.kernels = mweb.kernels;
    pegin.kernels[0].features = mw::Kernel::FEE_FEATURE_BIT | mw::Kernel::PEGIN_FEATURE_BIT;
    pegin.kernels[0].pegin_amount = 2 * COIN + fee;

    PartiallySignedTransaction pegout = mweb;
    pegout.outputs.clear();
    pegout.inputs[0].mweb_amount = 3 * COIN + fee;
    pegout.kernels[0].features = mw::Kernel::FEE_FEATURE_BIT | mw::Kernel::PEGOUT_FEATURE_BIT;
    pegout.kernels[0].pegouts.emplace_back(3 * COIN, script);

    // Exercise both output layers, multiple kernels, and multiple pegout destinations together.
    CKey other_key;
    other_key.MakeNewKey(true);
    const CTxDestination other_address = PKHash(other_key.GetPubKey());
    PartiallySignedTransaction mixed = pegout;
    mixed.inputs.insert(mixed.inputs.begin(), canonical_v2.inputs[0]);
    mixed.inputs[0].witness_utxo.nValue = COIN;
    mixed.inputs[1].mweb_amount = 9 * COIN + fee;
    mixed.outputs = {canonical_v2.outputs[0], mweb.outputs[0]};
    mixed.kernels.emplace_back();
    mixed.kernels[1].features = mw::Kernel::PEGOUT_FEATURE_BIT;
    mixed.kernels[1].pegouts.emplace_back(4 * COIN, GetScriptForDestination(other_address));

    // MWEB output metadata can contain a commitment without its recipient address.
    PartiallySignedTransaction unknown_address = mweb;
    unknown_address.outputs[0].mweb_stealth_address.reset();
    unknown_address.outputs[0].mweb_commit = Commitment::Transparent(2 * COIN);

    struct TestCase {
        PartiallySignedTransaction psbt;
        std::vector<std::pair<CTxDestination, CAmount>> recipients;
        CAmount total;
    };
    const std::vector<TestCase> cases{
        {canonical_v0, {{address, COIN}}, COIN},
        {canonical_v2, {{address, COIN}}, COIN},
        {mweb, {{mweb_address, 2 * COIN}}, 2 * COIN},
        {pegin, {{mweb_address, 2 * COIN}}, 2 * COIN},
        {pegout, {{address, 3 * COIN}}, 3 * COIN},
        {mixed, {{address, COIN}, {mweb_address, 2 * COIN}, {address, 3 * COIN}, {other_address, 4 * COIN}}, 10 * COIN},
        {unknown_address, {{CNoDestination{}, 2 * COIN}}, 2 * COIN},
    };

    QTemporaryDir directory;
    QVERIFY(directory.isValid());
    const bool native_dialogs_disabled = QApplication::testAttribute(Qt::AA_DontUseNativeDialogs);
    QApplication::setAttribute(Qt::AA_DontUseNativeDialogs);
    for (size_t i = 0; i < cases.size(); ++i) {
        const TestCase& test = cases[i];
        PSBTOperationsDialog dialog(nullptr, nullptr, &client_model);
        dialog.openWithPSBT(test.psbt);
        auto* description = dialog.findChild<QTextEdit*>("transactionDescription");
        QVERIFY(description);
        const QString text = description->toPlainText();
        QCOMPARE(text.count("Sends "), int(test.recipients.size()));
        QStringList filename_parts;
        for (const auto& [destination, amount] : test.recipients) {
            const QString encoded = QString::fromStdString(EncodeDestination(destination));
            const QString displayed = encoded.isEmpty() ? "(unknown)" : encoded;
            QVERIFY(text.contains(QString("Sends %1 to %2")
                .arg(BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, amount)).arg(displayed)));
            filename_parts.append(encoded + "-" + BitcoinUnits::format(unit, amount));
        }
        QVERIFY(text.contains("Pays transaction fee: " + BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, fee)));
        QVERIFY(text.contains("Total Amount: " + BitcoinUnits::formatWithUnit(unit, test.total, false, BitcoinUnits::SeparatorStyle::ALWAYS)));

        // Accept the real save dialog and check both its suggested filename and the saved PSBT bytes.
        const QString path = directory.filePath(QString("transaction-%1.psbt").arg(i));
        QString suggested_filename;
        QTimer::singleShot(0, [&] {
            auto* file_dialog = qobject_cast<QFileDialog*>(QApplication::activeModalWidget());
            if (!file_dialog) {
                if (QApplication::activeModalWidget()) QApplication::activeModalWidget()->close();
                return;
            }
            suggested_filename = QFileInfo(file_dialog->selectedFiles().value(0)).fileName();
            file_dialog->selectFile(path);
            // selectFile() keeps the existing filename when the dialog is already visible.
            if (auto* filename = file_dialog->findChild<QLineEdit*>("fileNameEdit")) {
                filename->setText(QFileInfo(path).fileName());
            }
            QMetaObject::invokeMethod(file_dialog, "accept", Qt::QueuedConnection);
        });
        dialog.saveTransaction();
        QCOMPARE(suggested_filename, filename_parts.join("-") + ".psbt");
        QFile file(path);
        QVERIFY2(file.open(QIODevice::ReadOnly), qPrintable(file.errorString()));
        CDataStream expected(SER_NETWORK, PROTOCOL_VERSION);
        expected << test.psbt;
        QCOMPARE(file.readAll(), QByteArray::fromStdString(expected.str()));
    }
    QApplication::setAttribute(Qt::AA_DontUseNativeDialogs, native_dialogs_disabled);

    // Missing UTXO information must not dereference an absent fee, and a known zero fee must be shown.
    PSBTOperationsDialog dialog(nullptr, nullptr, &client_model);
    auto* description = dialog.findChild<QTextEdit*>("transactionDescription");
    QVERIFY(description);
    canonical_v2.inputs[0].witness_utxo.SetNull();
    dialog.openWithPSBT(canonical_v2);
    QVERIFY(description->toPlainText().contains("Unable to calculate transaction fee or total transaction amount."));
    canonical_v2.inputs[0].witness_utxo = CTxOut(COIN, script);
    dialog.openWithPSBT(canonical_v2);
    QVERIFY(description->toPlainText().contains("Pays transaction fee: " + BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, 0)));
}

//! Wallet widgets must display correct sends, balances and PSBTs, manage payment requests, and honor MWEB selections.
//
// Test widgets can be debugged interactively calling show() on them and
// manually running the event loop, e.g.:
//
//     sendCoinsDialog.show();
//     QEventLoop().exec();
//
// This also requires overriding the default minimal Qt platform:
//
//     QT_QPA_PLATFORM=xcb     src/qt/test/test_litecoin-qt  # Linux
//     QT_QPA_PLATFORM=windows src/qt/test/test_litecoin-qt  # Windows
//     QT_QPA_PLATFORM=cocoa   src/qt/test/test_litecoin-qt  # macOS
void TestGUI(interfaces::Node& node)
{
    // Set up wallet and chain with 105 blocks (5 mature blocks for spending).
    TestChain100Setup test;
    for (int i = 0; i < 5; ++i) {
        test.CreateAndProcessBlock({}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    }
    auto wallet_loader = interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args));
    test.m_node.wallet_loader = wallet_loader.get();
    node.setContext(&test.m_node);
    const std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(node.context()->chain.get(), "", gArgs, CreateMockWalletDatabase());
    wallet->LoadWallet();
    wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    {
        LOCK(wallet->cs_wallet);
        wallet->SetupDescriptorScriptPubKeyMans();

        // Add the coinbase key
        FlatSigningProvider provider;
        std::string error;
        std::unique_ptr<Descriptor> desc = Parse("combo(" + EncodeSecret(test.coinbaseKey) + ")", provider, error, /* require_checksum=*/ false);
        assert(desc);
        WalletDescriptor w_desc(std::move(desc), 0, 0, 1, 1);
        if (!wallet->AddWalletDescriptor(w_desc, provider, "", false)) assert(false);
        CTxDestination dest = GetDestinationForKey(test.coinbaseKey.GetPubKey(), wallet->m_default_address_type, SecretKey{});
        wallet->SetAddressBook(dest, "", "receive");
        wallet->SetLastBlockProcessed(105, WITH_LOCK(node.context()->chainman->GetMutex(), return node.context()->chainman->ActiveChain().Tip()->GetBlockHash()));
    }
    {
        WalletRescanReserver reserver(*wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet->ScanForWalletTransactions(Params().GetConsensus().hashGenesisBlock, /*start_height=*/0, /*max_height=*/{}, reserver, /*fUpdate=*/true, /*save_progress=*/false);
        QCOMPARE(result.status, CWallet::ScanResult::SUCCESS);
        QCOMPARE(result.last_scanned_block, WITH_LOCK(node.context()->chainman->GetMutex(), return node.context()->chainman->ActiveChain().Tip()->GetBlockHash()));
        QVERIFY(result.last_failed_block.IsNull());
    }
    wallet->SetBroadcastTransactions(true);

    // Create widgets for sending coins and listing transactions.
    std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    SendCoinsDialog sendCoinsDialog(platformStyle.get());
    TransactionView transactionView(platformStyle.get());
    OptionsModel optionsModel(node);
    bilingual_str error;
    QVERIFY(optionsModel.Init(error));
    ClientModel clientModel(node, &optionsModel);
    WalletContext& context = *node.walletLoader().context();
    AddWallet(context, wallet);
    WalletModel walletModel(interfaces::MakeWallet(context, wallet), clientModel, platformStyle.get());
    RemoveWallet(context, wallet, /* load_on_start= */ std::nullopt);
    sendCoinsDialog.setModel(&walletModel);
    transactionView.setModel(&walletModel);

    // Update walletModel cached balance which will trigger an update for the 'labelBalance' QLabel.
    walletModel.pollBalanceChanged();
    // Check balance in send dialog
    CompareBalance(walletModel, walletModel.wallet().getBalance(), sendCoinsDialog.findChild<QLabel*>("labelBalance"));

    TestSendCoinsRecipientAmounts(walletModel, *wallet);

    // Send two transactions, and verify they are added to transaction list.
    TransactionTableModel* transactionTableModel = walletModel.getTransactionTableModel();
    QCOMPARE(transactionTableModel->rowCount({}), 105);
    uint256 txid1 = SendCoins(*wallet.get(), sendCoinsDialog, PKHash(), 5 * COIN, false /* rbf */);
    uint256 txid2 = SendCoins(*wallet.get(), sendCoinsDialog, PKHash(), 10 * COIN, true /* rbf */);
    QCOMPARE(transactionTableModel->rowCount({}), 107);
    QVERIFY(FindTx(*transactionTableModel, txid1).isValid());
    QVERIFY(FindTx(*transactionTableModel, txid2).isValid());

    // Call bumpfee. Test disabled, canceled, enabled, then failing cases.
    // Litecoin: Disable BumpFee tests
    //BumpFee(transactionView, txid1, true /* expect disabled */, "not BIP 125 replaceable" /* expected error */, false /* cancel */);
    //BumpFee(transactionView, txid2, false /* expect disabled */, {} /* expected error */, true /* cancel */);
    //BumpFee(transactionView, txid2, false /* expect disabled */, {} /* expected error */, false /* cancel */);
    //BumpFee(transactionView, txid2, true /* expect disabled */, "already bumped" /* expected error */, false /* cancel */);

    // Check current balance on OverviewPage
    OverviewPage overviewPage(platformStyle.get());
    overviewPage.setWalletModel(&walletModel);
    walletModel.pollBalanceChanged(); // Manual balance polling update
    CompareBalance(walletModel, walletModel.wallet().getBalance(), overviewPage.findChild<QLabel*>("labelBalance"));

    // Check Request Payment button
    ReceiveCoinsDialog receiveCoinsDialog(platformStyle.get());
    receiveCoinsDialog.setModel(&walletModel);
    RecentRequestsTableModel* requestTableModel = walletModel.getRecentRequestsTableModel();

    // Label input
    QLineEdit* labelInput = receiveCoinsDialog.findChild<QLineEdit*>("reqLabel");
    labelInput->setText("TEST_LABEL_1");

    // Amount input
    BitcoinAmountField* amountInput = receiveCoinsDialog.findChild<BitcoinAmountField*>("reqAmount");
    amountInput->setValue(1);

    // Message input
    QLineEdit* messageInput = receiveCoinsDialog.findChild<QLineEdit*>("reqMessage");
    messageInput->setText("TEST_MESSAGE_1");
    int initialRowCount = requestTableModel->rowCount({});
    QPushButton* requestPaymentButton = receiveCoinsDialog.findChild<QPushButton*>("receiveButton");
    requestPaymentButton->click();
    QString address;
    for (QWidget* widget : QApplication::topLevelWidgets()) {
        if (widget->inherits("ReceiveRequestDialog")) {
            ReceiveRequestDialog* receiveRequestDialog = qobject_cast<ReceiveRequestDialog*>(widget);
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("payment_header")->text(), QString("Payment information"));
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("uri_tag")->text(), QString("URI:"));
            QString uri = receiveRequestDialog->QObject::findChild<QLabel*>("uri_content")->text();
            QCOMPARE(uri.count("litecoin:"), 2);
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("address_tag")->text(), QString("Address:"));
            QVERIFY(address.isEmpty());
            address = receiveRequestDialog->QObject::findChild<QLabel*>("address_content")->text();
            QVERIFY(!address.isEmpty());

            QCOMPARE(uri.count("amount=0.00000001"), 2);
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("amount_tag")->text(), QString("Amount:"));
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("amount_content")->text(), QString::fromStdString("0.00000001 " + CURRENCY_UNIT));

            QCOMPARE(uri.count("label=TEST_LABEL_1"), 2);
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("label_tag")->text(), QString("Label:"));
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("label_content")->text(), QString("TEST_LABEL_1"));

            QCOMPARE(uri.count("message=TEST_MESSAGE_1"), 2);
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("message_tag")->text(), QString("Message:"));
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("message_content")->text(), QString("TEST_MESSAGE_1"));
        }
    }

    // Clear button
    QPushButton* clearButton = receiveCoinsDialog.findChild<QPushButton*>("clearButton");
    clearButton->click();
    QCOMPARE(labelInput->text(), QString(""));
    QCOMPARE(amountInput->value(), CAmount(0));
    QCOMPARE(messageInput->text(), QString(""));

    // Check addition to history
    int currentRowCount = requestTableModel->rowCount({});
    QCOMPARE(currentRowCount, initialRowCount+1);

    // Check addition to wallet
    std::vector<std::string> requests = walletModel.wallet().getAddressReceiveRequests();
    QCOMPARE(requests.size(), size_t{1});
    RecentRequestEntry entry;
    CDataStream{MakeUCharSpan(requests[0]), SER_DISK, CLIENT_VERSION} >> entry;
    QCOMPARE(entry.nVersion, int{1});
    QCOMPARE(entry.id, int64_t{1});
    QVERIFY(entry.date.isValid());
    QCOMPARE(entry.recipient.address, address);
    QCOMPARE(entry.recipient.label, QString{"TEST_LABEL_1"});
    QCOMPARE(entry.recipient.amount, CAmount{1});
    QCOMPARE(entry.recipient.message, QString{"TEST_MESSAGE_1"});
    QCOMPARE(entry.recipient.sPaymentRequest, std::string{});
    QCOMPARE(entry.recipient.authenticatedMerchant, QString{});

    // Check Remove button
    QTableView* table = receiveCoinsDialog.findChild<QTableView*>("recentRequestsView");
    table->selectRow(currentRowCount-1);
    QPushButton* removeRequestButton = receiveCoinsDialog.findChild<QPushButton*>("removeRequestButton");
    removeRequestButton->click();
    QCOMPARE(requestTableModel->rowCount({}), currentRowCount-1);

    // Check removal from wallet
    QCOMPARE(walletModel.wallet().getAddressReceiveRequests().size(), size_t{0});

    TestMWEBCoinControl(walletModel, *wallet, platformStyle.get());
    TestSendCoinsAddressEntry(walletModel, platformStyle.get());
    TestPSBTOperations(clientModel);
}

} // namespace

void WalletTests::walletTests()
{
#ifdef Q_OS_MACOS
    if (QApplication::platformName() == "minimal") {
        // Disable for mac on "minimal" platform to avoid crashes inside the Qt
        // framework when it tries to look up unimplemented cocoa functions,
        // and fails to handle returned nulls
        // (https://bugreports.qt.io/browse/QTBUG-49686).
        QWARN("Skipping WalletTests on mac build with 'minimal' platform set due to Qt bugs. To run AppTests, invoke "
              "with 'QT_QPA_PLATFORM=cocoa test_litecoin-qt' on mac, or else use a linux or windows build.");
        return;
    }
#endif
    TestGUI(m_node);
}
