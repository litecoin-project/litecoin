// Copyright (c) 2014-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/initexecutor.h>

#include <interfaces/node.h>
#include <node/interface_ui.h>
#include <util/system.h>
#include <util/threadnames.h>
#include <util/translation.h>

#include <exception>

#include <QDebug>
#include <QMetaObject>
#include <QObject>
#include <QString>
#include <QThread>

InitExecutor::InitExecutor(interfaces::Node& node)
    : QObject(), m_node(node)
{
    m_context.moveToThread(&m_thread);
    m_thread.start();
}

InitExecutor::~InitExecutor()
{
    qDebug() << __func__ << ": Stopping thread";
    m_thread.quit();
    m_thread.wait();
    qDebug() << __func__ << ": Stopped thread";
}

void InitExecutor::handleRunawayException(const std::exception* e)
{
    PrintExceptionContinue(e, "Runaway exception");
    Q_EMIT runawayException(QString::fromStdString(m_node.getWarnings().translated));
}

void InitExecutor::initialize()
{
    QMetaObject::invokeMethod(&m_context, [this] {
        try {
            util::ThreadRename("qt-init");
            qDebug() << "Running initialization in thread";
            interfaces::BlockAndHeaderTipInfo tip_info;
            const auto confirm_db_upgrade = [this] {
                const bilingual_str warning = _(
                    "This version of Litecoin Core needs to upgrade your node database.\n\n"
                    "This upgrade is one-way. Older versions of Litecoin Core will not be able to use this database.\n\n"
                    "To go back, you will need to restore a backup made before this upgrade or download the blockchain again.\n\n"
                    "Do you want to upgrade now?");
                const bool accepted = uiInterface.ThreadSafeQuestion(
                    warning, warning.original, _("Database upgrade").translated,
                    CClientUIInterface::ICON_WARNING | CClientUIInterface::MODAL |
                        CClientUIInterface::BTN_OK | CClientUIInterface::BTN_CANCEL);
                if (!accepted) m_node.startShutdown();
                return accepted;
            };
            bool rv = m_node.appInitMain(&tip_info, confirm_db_upgrade);
            Q_EMIT initializeResult(rv, tip_info);
        } catch (const std::exception& e) {
            handleRunawayException(&e);
        } catch (...) {
            handleRunawayException(nullptr);
        }
    });
}

void InitExecutor::shutdown()
{
    QMetaObject::invokeMethod(&m_context, [this] {
        try {
            qDebug() << "Running Shutdown in thread";
            m_node.appShutdown();
            qDebug() << "Shutdown finished";
            Q_EMIT shutdownResult();
        } catch (const std::exception& e) {
            handleRunawayException(&e);
        } catch (...) {
            handleRunawayException(nullptr);
        }
    });
}
