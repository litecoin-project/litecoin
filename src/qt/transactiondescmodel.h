#ifndef BITCOIN_QT_TRANSACTIONDESCMODEL_H
#define BITCOIN_QT_TRANSACTIONDESCMODEL_H

#include <qt/bitcoinunits.h>

#include <QObject>
#include <QString>
#include <optional>

namespace wallet {
class WalletTxRecord;
}

namespace interfaces {
class Node;
class Wallet;
struct WalletTx;
struct WalletTxStatus;
}

struct TransactionDescModel
{
    struct Source {
        enum class Type {
            GENERATED,
            ONLINE,
            UNKNOWN
        };

        std::optional<QString> from;
    };
    std::optional<Source> source;

    struct To {
        QString address;
        std::optional<bool> spendable;
        std::optional<QString> label;
    };
    std::optional<To> destination;
};

#endif // BITCOIN_QT_TRANSACTIONDESCMODEL_H
