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
#include <qt/optionsmodel.h>
#include <qt/overviewpage.h>
#include <qt/platformstyle.h>
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
#include <wallet/wallet.h>

#include <algorithm>
#include <chrono>
#include <memory>

#include <QAbstractButton>
#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>
#include <QTextEdit>
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
        recipient.type = SendCoinsRecipient::REGULAR;
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

//! Simple qt wallet tests.
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
