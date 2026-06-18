// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#include "ConnectionsWidget.h"
#include "core/RiskAnalyzer.h"
#include "core/ThreatDatabase.h"
#include "core/IpReputationDb.h"
#include "platform/windows/ConnectionEnumerator.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QFont>
#include <QFileInfo>
#include <QLineEdit>
#include <QColor>
#include <QProgressDialog>
#include <QApplication>
#include <QMenu>
#include <QMessageBox>
#include "core/AiAssistant.h"
#include "gui/AiResultDialog.h"

static QString repStatusText(MalwareResult::Status s)
{
    switch (s) {
    case MalwareResult::Clean:      return QStringLiteral("Clean");
    case MalwareResult::Suspicious: return QStringLiteral("Suspicious");
    case MalwareResult::Malicious:  return QStringLiteral("Malicious");
    default:                        return QStringLiteral("Unknown");
    }
}

ConnectionsWidget::ConnectionsWidget(QWidget *parent)
    : QWidget(parent)
{
    setupUi();
}

void ConnectionsWidget::setupUi()
{
    auto root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    auto topBar = new QWidget;
    auto topLayout = new QHBoxLayout(topBar);
    topLayout->setContentsMargins(4, 4, 4, 4);

    m_askAiBtn = new QPushButton(QStringLiteral("Ask AI"));
    m_askAiBtn->setCursor(Qt::PointingHandCursor);
    m_askAiBtn->setEnabled(false);
    connect(m_askAiBtn, &QPushButton::clicked, this, &ConnectionsWidget::onAskAi);
    topLayout->addWidget(m_askAiBtn);

    auto refreshBtn = new QPushButton(QStringLiteral("Refresh Connections"));
    refreshBtn->setCursor(Qt::PointingHandCursor);
    connect(refreshBtn, &QPushButton::clicked, this, &ConnectionsWidget::refresh);
    topLayout->addWidget(refreshBtn);

    topLayout->addStretch();

    auto pageTitle = new QLabel(QStringLiteral("Active Connections"));
    QFont titleFont = pageTitle->font();
    titleFont.setPointSize(14);
    titleFont.setBold(true);
    pageTitle->setFont(titleFont);
    topLayout->addWidget(pageTitle);
    topLayout->addStretch();

    root->addWidget(topBar);

    auto searchBar = new QWidget;
    auto searchLayout = new QHBoxLayout(searchBar);
    searchLayout->setContentsMargins(4, 2, 4, 2);
    auto searchEdit = new QLineEdit;
    searchEdit->setPlaceholderText(QStringLiteral("Filter connections..."));
    searchEdit->setClearButtonEnabled(true);
    searchLayout->addWidget(new QLabel(QStringLiteral("Search:")), 0);
    searchLayout->addWidget(searchEdit, 1);
    root->addWidget(searchBar);

    connect(searchEdit, &QLineEdit::textChanged, this, [this](const QString &text) {
        for (int i = 0; i < m_table->rowCount(); ++i) {
            auto item = m_table->item(i, 0);
            bool match = !item || item->text().contains(text, Qt::CaseInsensitive);
            m_table->setRowHidden(i, !match);
        }
    });

    m_table = new QTableWidget;
    m_table->setColumnCount(12);
    m_table->setHorizontalHeaderLabels({
        QStringLiteral("Application"),
        QStringLiteral("PID"),
        QStringLiteral("Protocol"),
        QStringLiteral("Local Address"),
        QStringLiteral("Local Port"),
        QStringLiteral("Remote Address"),
        QStringLiteral("Remote Port"),
        QStringLiteral("IP Rep"),
        QStringLiteral("State"),
        QStringLiteral("Reputation"),
        QStringLiteral("Risky Dir"),
        QStringLiteral("Suspicious"),
    });
    m_table->horizontalHeader()->setStretchLastSection(false);
    m_table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    for (int c = 1; c < m_table->columnCount(); ++c)
        m_table->horizontalHeader()->setSectionResizeMode(c, QHeaderView::ResizeToContents);
    m_table->verticalHeader()->hide();
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->setSortingEnabled(true);
    root->addWidget(m_table, 1);

    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_table, &QWidget::customContextMenuRequested, this, &ConnectionsWidget::onTableContextMenu);

    connect(m_table, &QTableWidget::itemSelectionChanged, this, [this]() {
        m_askAiBtn->setEnabled(m_table->currentRow() >= 0 && AiAssistant::isModelLoaded());
    });

    auto bottomBar = new QWidget;
    auto bottomLayout = new QHBoxLayout(bottomBar);
    bottomLayout->setContentsMargins(4, 4, 4, 4);

    m_statusLabel = new QLabel;
    bottomLayout->addWidget(m_statusLabel);
    bottomLayout->addStretch();

    auto backBtn = new QPushButton(QStringLiteral("<< Dashboard"));
    backBtn->setCursor(Qt::PointingHandCursor);
    connect(backBtn, &QPushButton::clicked, this, &ConnectionsWidget::backToOverview);
    bottomLayout->addWidget(backBtn);

    root->addWidget(bottomBar);
}

void ConnectionsWidget::refresh()
{
    auto conns = ConnectionEnumerator::enumerateConnections();

    m_table->setRowCount(conns.size());
    m_table->setUpdatesEnabled(false);
    m_table->setSortingEnabled(false);

    int suspiciousCount = 0;

    for (int i = 0; i < conns.size(); ++i) {
        const auto &conn = conns[i];

        auto protoItem = new QTableWidgetItem(conn.protocolStr);
        protoItem->setTextAlignment(Qt::AlignCenter);

        QString displayName = conn.processName.isEmpty()
            ? QStringLiteral("(PID %1)").arg(conn.pid)
            : conn.processName;

        auto nameItem = new QTableWidgetItem(displayName);
        nameItem->setData(Qt::UserRole, conn.processPath);
        QFont f = nameItem->font();
        if (!conn.processPath.isEmpty())
            f.setBold(true);
        nameItem->setFont(f);
        nameItem->setToolTip(conn.processPath.isEmpty()
            ? QStringLiteral("Process path unavailable (access denied or terminated)")
            : conn.processPath);

        m_table->setItem(i, 0, nameItem);
        m_table->setItem(i, 1, new QTableWidgetItem(QString::number(conn.pid)));
        m_table->setItem(i, 2, protoItem);
        m_table->setItem(i, 3, new QTableWidgetItem(conn.localAddr));
        m_table->setItem(i, 4, new QTableWidgetItem(QString::number(conn.localPort)));

        if (conn.protocol == 6 && conn.state == QStringLiteral("LISTEN")) {
            m_table->setItem(i, 5, new QTableWidgetItem(QStringLiteral("*")));
            m_table->setItem(i, 6, new QTableWidgetItem(QStringLiteral("*")));
        } else {
            m_table->setItem(i, 5, new QTableWidgetItem(conn.remoteAddr));
            m_table->setItem(i, 6, new QTableWidgetItem(
                conn.remotePort > 0 ? QString::number(conn.remotePort) : QStringLiteral("*")));
        }

        auto ipRepRes = IpReputationDb::checkIp(conn.remoteAddr);
        auto ipRepItem = new QTableWidgetItem;
        if (ipRepRes.status == IpReputationResult::Suspicious) {
            ipRepItem->setText(QStringLiteral("Suspicious"));
            ipRepItem->setToolTip(ipRepRes.label);
            ipRepItem->setForeground(QColor(Qt::red));
            QFont rf = ipRepItem->font();
            rf.setBold(true);
            ipRepItem->setFont(rf);
        } else if (ipRepRes.status == IpReputationResult::Safe) {
            ipRepItem->setText(QStringLiteral("Safe"));
            ipRepItem->setToolTip(ipRepRes.label);
            ipRepItem->setForeground(QColor(0x2E, 0x7D, 0x32));
        } else {
            ipRepItem->setText(QStringLiteral("Unknown"));
            ipRepItem->setToolTip(QString());
            ipRepItem->setForeground(QColor(0x99, 0x99, 0x99));
        }
        m_table->setItem(i, 7, ipRepItem);

        m_table->setItem(i, 8, new QTableWidgetItem(conn.state));

        if (!conn.processPath.isEmpty()) {
            auto repRes = KnownMalwareDb::checkApp(conn.processPath);
            auto repItem = new QTableWidgetItem;
            if (repRes.status == MalwareResult::Malicious) {
                repItem->setText(QStringLiteral("Malicious"));
                repItem->setToolTip(repRes.details);
                repItem->setForeground(QColor(Qt::red));
                QFont rf = repItem->font();
                rf.setBold(true);
                repItem->setFont(rf);
            } else if (repRes.status == MalwareResult::Suspicious) {
                repItem->setText(QStringLiteral("Suspicious"));
                repItem->setToolTip(repRes.details);
                repItem->setForeground(QColor(0xCC, 0x88, 0x00));
                QFont rf = repItem->font();
                rf.setBold(true);
                repItem->setFont(rf);
            } else if (repRes.status == MalwareResult::Clean) {
                repItem->setText(QStringLiteral("Clean"));
                repItem->setToolTip(QStringLiteral("No known malware association"));
                repItem->setForeground(QColor(0x2E, 0x7D, 0x32));
            } else {
                repItem->setText(QStringLiteral("Not checked"));
                repItem->setToolTip(QString());
            }
            m_table->setItem(i, 9, repItem);

            QString dirInfo = RiskAnalyzer::suspiciousPathInfo(conn.processPath);
            auto dirItem = new QTableWidgetItem;
            if (dirInfo.isEmpty()) {
                dirItem->setText(QStringLiteral("OK"));
                dirItem->setToolTip(QStringLiteral("Runs from standard directory"));
                dirItem->setForeground(QColor(0x2E, 0x7D, 0x32));
            } else {
                dirItem->setText(QStringLiteral("Warning"));
                dirItem->setToolTip(dirInfo);
                dirItem->setForeground(QColor(0xCC, 0x88, 0x00));
            }
            m_table->setItem(i, 10, dirItem);

            ConnectionInfo assessed = conn;
            assessed.repResult = repRes;
            assessed.dirInfo = dirInfo;
            assessed.ipRepResult = ipRepRes;
            assessed.suspiciousPort = (conn.remotePort > 0)
                && ThreatDatabase::isPortDangerous(conn.remotePort);

            if (assessed.suspiciousPort)
                ++suspiciousCount;
            updateSuspiciousRow(i, assessed);

        } else {
            auto unknownItem = new QTableWidgetItem(QStringLiteral("N/A"));
            unknownItem->setForeground(QColor(0x99, 0x99, 0x99));
            m_table->setItem(i, 7, unknownItem->clone());
            m_table->setItem(i, 8, unknownItem);
            m_table->setItem(i, 9, unknownItem->clone());
            m_table->setItem(i, 10, unknownItem->clone());

            auto suspItem = new QTableWidgetItem(QStringLiteral("-"));
            suspItem->setTextAlignment(Qt::AlignCenter);
            suspItem->setForeground(QColor(0x99, 0x99, 0x99));
            m_table->setItem(i, 11, suspItem);
        }
    }

    m_statusLabel->setText(
        QStringLiteral("Connections: %1 | Suspicious: %2")
            .arg(conns.size()).arg(suspiciousCount));

    m_table->setSortingEnabled(true);
    m_table->setUpdatesEnabled(true);

    emit connStatsUpdated(conns.size(), suspiciousCount);
}

void ConnectionsWidget::onAskAi()
{
    if (!AiAssistant::isModelLoaded()) {
        QMessageBox::information(this, QStringLiteral("AI Assistant"),
            QStringLiteral("No AI model loaded.\n\n"
                           "Go to Options → AI Settings to configure the model path."));
        return;
    }

    int row = m_table->currentRow();
    if (row < 0) return;

    auto nameItem = m_table->item(row, 0);
    if (!nameItem) return;

    QString appPath = nameItem->data(Qt::UserRole).toString();
    if (appPath.isEmpty()) return;

    FirewallRule rule;
    rule.name = QStringLiteral("Connection: %1").arg(nameItem->text());
    rule.applicationPath = appPath;

    auto protoItem = m_table->item(row, 2);
    if (protoItem) {
        rule.protocol = (protoItem->text() == QStringLiteral("TCP"))
            ? FirewallRule::Protocol::TCP : FirewallRule::Protocol::UDP;
    }
    auto localPortItem = m_table->item(row, 4);
    if (localPortItem) {
        bool ok;
        int p = localPortItem->text().toInt(&ok);
        if (ok && p > 0) rule.localPorts.append(p);
    }
    auto remotePortItem = m_table->item(row, 6);
    if (remotePortItem) {
        bool ok;
        int p = remotePortItem->text().toInt(&ok);
        if (ok && p > 0) rule.remotePorts.append(p);
    }
    auto remoteAddrItem = m_table->item(row, 5);
    if (remoteAddrItem && remoteAddrItem->text() != QStringLiteral("*"))
        rule.remoteAddresses.append(remoteAddrItem->text());

    rule.direction = FirewallRule::Direction::Inbound;

    RiskResult risk = RiskAnalyzer::analyze(rule);
    auto dialog = new AiResultDialog(rule, risk, this);
    dialog->open();
}

void ConnectionsWidget::onTableContextMenu(const QPoint &pos)
{
    auto idx = m_table->indexAt(pos);
    if (!idx.isValid()) return;

    bool hasModel = AiAssistant::isModelLoaded();

    QMenu menu(this);
    QAction *askAiAction = menu.addAction(QStringLiteral("Ask AI"));
    askAiAction->setEnabled(hasModel);
    connect(askAiAction, &QAction::triggered, this, &ConnectionsWidget::onAskAi);

    menu.exec(m_table->viewport()->mapToGlobal(pos));
}

void ConnectionsWidget::updateAiButtonState()
{
    m_askAiBtn->setEnabled(m_table->currentRow() >= 0 && AiAssistant::isModelLoaded());
}

void ConnectionsWidget::updateSuspiciousRow(int row, const ConnectionInfo &conn)
{
    int score = 0;

    if (conn.repResult.status != MalwareResult::Clean
        && conn.repResult.status != MalwareResult::Unknown)
        ++score;

    if (!conn.dirInfo.isEmpty())
        ++score;

    if (conn.suspiciousPort)
        ++score;

    if (conn.ipRepResult.status == IpReputationResult::Suspicious)
        score += 2;

    auto *suspItem = m_table->item(row, 11);
    if (!suspItem) {
        suspItem = new QTableWidgetItem;
        m_table->setItem(row, 11, suspItem);
    }
    suspItem->setText(QString::number(score));
    suspItem->setToolTip(suspiciousTooltip(conn));
    suspItem->setTextAlignment(Qt::AlignCenter);
    if (score == 0)
        suspItem->setForeground(QColor(0x2E, 0x7D, 0x32));
    else if (score <= 2)
        suspItem->setForeground(QColor(0xCC, 0x88, 0x00));
    else
        suspItem->setForeground(QColor(Qt::red));
    QFont sf = suspItem->font();
    sf.setBold(score >= 2);
    suspItem->setFont(sf);
}

QString ConnectionsWidget::suspiciousTooltip(const ConnectionInfo &conn) const
{
    QStringList factors;
    if (conn.repResult.status != MalwareResult::Clean
        && conn.repResult.status != MalwareResult::Unknown)
        factors.append(QStringLiteral("+1 Reputation (%1)")
            .arg(repStatusText(conn.repResult.status)));
    if (!conn.dirInfo.isEmpty())
        factors.append(QStringLiteral("+1 Directory (%1)").arg(conn.dirInfo));
    if (conn.suspiciousPort)
        factors.append(QStringLiteral("+1 Dangerous port (%1)").arg(conn.remotePort));
    if (conn.ipRepResult.status == IpReputationResult::Suspicious)
        factors.append(QStringLiteral("+2 IP reputation (%1)").arg(conn.ipRepResult.label));

    return factors.isEmpty()
        ? QStringLiteral("No suspicious indicators")
        : factors.join(QStringLiteral("\n"));
}
