// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#include "MainWindow.h"
#include "ui_MainWindow.h"

#include "OverviewWidget.h"
#include "AppsWidget.h"
#include "ConnectionsWidget.h"
#include "RuleTableModel.h"
#include "RuleDialog.h"
#include "AiResultDialog.h"
#include "OptionsDialog.h"
#include "core/FirewallManager.h"
#include "core/IFirewall.h"
#include "core/ThreatDatabase.h"
#include "core/BackupManager.h"
#include "core/AiAssistant.h"
#include <QDebug>
#include "core/RiskAnalyzer.h"
#include "platform/windows/Elevation.h"

#include <QStackedWidget>
#include <QTableView>
#include <QStatusBar>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QToolBar>
#include <QLabel>
#include <QPushButton>
#include <QAction>
#include <QMessageBox>
#include <QHeaderView>
#include <QApplication>
#include <QCoreApplication>
#include <QTemporaryFile>
#include <QDataStream>
#include <QTimer>
#include <QSettings>
#include <QSortFilterProxyModel>
#include <QLineEdit>
#include <QMenu>

MainWindow::MainWindow(std::unique_ptr<FirewallManager> manager)
    : m_manager(std::move(manager))
{
    if (m_manager)
        m_firewall = m_manager->firewall();

    setupUi();
}

MainWindow::~MainWindow() = default;

void MainWindow::setupUi()
{
    ui = std::make_unique<Ui::MainWindow>();
    ui->setupUi(this);

    m_refreshAction = ui->actionRefresh;
    m_addAction = ui->actionAddRule;
    m_editAction = ui->actionEditRule;
    m_deleteAction = ui->actionDeleteRule;
    m_toggleEnabledAction = ui->actionToggleEnabled;
    m_riskyOnlyAction = ui->actionShowRiskyOnly;

    m_model = new RuleTableModel(this);
    m_proxy = new QSortFilterProxyModel(this);
    m_proxy->setSourceModel(m_model);
    m_proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_proxy->setFilterKeyColumn(-1);

    ui->tableView->setModel(m_proxy);
    ui->tableView->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    ui->tableView->viewport()->setAttribute(Qt::WA_Hover, true);

    connect(ui->searchEdit, &QLineEdit::textChanged, this, [this](const QString &text) {
        if (!m_riskyOnlyAction->isChecked())
            m_proxy->setFilterFixedString(text);
        updateStatusBar();
    });

    connect(m_riskyOnlyAction, &QAction::toggled, this, [this](bool checked) {
        if (checked) {
            m_proxy->setFilterKeyColumn(RuleTableModel::ColRisk);
            m_proxy->setFilterRegularExpression(
                QStringLiteral("Medium|High|Critical"));
            ui->searchEdit->setEnabled(false);
        } else {
            m_proxy->setFilterKeyColumn(-1);
            m_proxy->setFilterFixedString(ui->searchEdit->text());
            ui->searchEdit->setEnabled(true);
        }
        updateStatusBar();
    });

    connect(m_refreshAction, &QAction::triggered, this, &MainWindow::onRefresh);
    connect(m_addAction, &QAction::triggered, this, &MainWindow::onAddRule);
    connect(m_editAction, &QAction::triggered, this, &MainWindow::onEditRule);
    connect(m_deleteAction, &QAction::triggered, this, &MainWindow::onDeleteRule);
    connect(m_toggleEnabledAction, &QAction::triggered, this, &MainWindow::onToggleEnabled);

    m_askAiAction = ui->actionAskAi;
    connect(m_askAiAction, &QAction::triggered, this, &MainWindow::onAskAi);

    m_tableContextMenu = new QMenu(this);
    m_tableContextMenu->addAction(ui->actionAskAi);

    m_tableContextMenu->addSeparator();
    m_tableContextMenu->addAction(m_addAction);
    m_tableContextMenu->addAction(m_editAction);
    m_tableContextMenu->addAction(m_deleteAction);
    m_tableContextMenu->addAction(m_toggleEnabledAction);

    ui->tableView->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ui->tableView, &QWidget::customContextMenuRequested,
            this, &MainWindow::onTableContextMenu);

    connect(ui->tableView->selectionModel(), &QItemSelectionModel::currentRowChanged,
            this, [this]() { updateStatusBar(); });

    m_overview = new OverviewWidget(m_firewall);
    connect(m_overview, &OverviewWidget::manageRulesClicked, this, &MainWindow::showRules);
    connect(m_overview, &OverviewWidget::manageAppsClicked, this, &MainWindow::showApps);
    connect(m_overview, &OverviewWidget::manageConnectionsClicked, this, &MainWindow::showConnections);
    connect(m_overview, &OverviewWidget::optionsChanged, this, &MainWindow::onOptionsChanged);
    connect(m_overview, &OverviewWidget::aiSettingsClicked, this, &MainWindow::onAiSettings);

    auto *ovLayout = new QVBoxLayout(ui->overviewPage);
    ovLayout->setContentsMargins(0, 0, 0, 0);
    ovLayout->addWidget(m_overview);

    m_apps = new AppsWidget(m_firewall);
    connect(m_apps, &AppsWidget::showRulesForApp, this, &MainWindow::showRulesForApp);
    connect(m_apps, &AppsWidget::backToOverview, this, &MainWindow::showOverview);
    connect(m_apps, &AppsWidget::topSuspiciousAppsUpdated, this, [this](const QStringList &names, const QList<int> &scores) {
        m_overview->setTopSuspiciousApps(names, scores);
    });

    auto *appLayout = new QVBoxLayout(ui->appsPage);
    appLayout->setContentsMargins(0, 0, 0, 0);
    appLayout->addWidget(m_apps);

    m_connections = new ConnectionsWidget;
    connect(m_connections, &ConnectionsWidget::backToOverview, this, &MainWindow::showOverview);
    auto *connLayout = new QVBoxLayout(ui->connectionsPage);
    connLayout->setContentsMargins(0, 0, 0, 0);
    connLayout->addWidget(m_connections);

    connect(ui->backButton, &QPushButton::clicked, this, &MainWindow::showOverview);

    ui->toolBar->hide();
    ui->stackedWidget->setCurrentIndex(0);

    m_refreshTimer = new QTimer(this);
    connect(m_refreshTimer, &QTimer::timeout, this, &MainWindow::onAutoRefresh);
    applyRefreshSettings();

    QTimer::singleShot(0, this, [this]() { m_apps->refresh(); });

    QTimer::singleShot(0, this, &MainWindow::loadAiModel);
}

void MainWindow::applyRefreshSettings()
{
    QSettings s(QStringLiteral("Vigil Fluminis"), QStringLiteral("Vigil Fluminis"));
    bool enabled = s.value(QStringLiteral("autorefresh/enabled"), false).toBool();
    int interval = s.value(QStringLiteral("autorefresh/interval"), 30).toInt();

    m_refreshTimer->stop();
    if (enabled)
        m_refreshTimer->start(interval * 1000);
}

void MainWindow::showOverview()
{
    ui->toolBar->hide();
    m_overview->refresh();
    ui->stackedWidget->setCurrentIndex(0);
}

void MainWindow::showRules()
{
    ui->toolBar->show();
    m_proxy->setFilterFixedString(QString());
    loadRules();
    ui->stackedWidget->setCurrentIndex(1);
}

void MainWindow::showApps()
{
    ui->toolBar->hide();
    m_apps->refresh();
    ui->stackedWidget->setCurrentIndex(2);
}

void MainWindow::showConnections()
{
    ui->toolBar->hide();
    m_connections->refresh();
    ui->stackedWidget->setCurrentIndex(3);
}

void MainWindow::showRulesForApp(const QString &appPath)
{
    ui->toolBar->show();
    m_proxy->setFilterFixedString(appPath);
    loadRules();
    ui->stackedWidget->setCurrentIndex(1);
}

void MainWindow::loadRules()
{
    if (!m_firewall)
        return;

    auto rules = m_firewall->rules();
    m_model->setRules(rules);
    updateStatusBar();

    if (!m_backedUp) {
        BackupManager::createBackup(rules);
        m_backedUp = true;
    }
}

void MainWindow::updateStatusBar()
{
    if (!m_firewall) {
        ui->statusLabel->setText(QStringLiteral("No firewall backend"));
        return;
    }

    int total = m_model->ruleCount();
    int shown = m_proxy->rowCount();
    QString filter = m_proxy->filterRegularExpression().pattern();

    QString text = QStringLiteral("Firewall: %1")
        .arg(m_firewall->firewallEnabled()
                 ? QStringLiteral("Enabled") : QStringLiteral("Disabled"));

    if (filter.isEmpty()) {
        text += QStringLiteral(" | Rules: %1").arg(total);
    } else {
        text += QStringLiteral(" | Rules: %1 / %2 (filtered: %3)")
            .arg(shown).arg(total).arg(filter);
    }

    auto current = m_proxy->mapToSource(ui->tableView->currentIndex());
    if (current.isValid()) {
        const auto &rule = m_model->ruleAt(current.row());
        auto risks = ThreatDatabase::riskDescriptions(rule);
        if (!risks.isEmpty())
            text += QStringLiteral(" | %1").arg(risks.first());
    }

    ui->statusLabel->setText(text);
}

void MainWindow::onRefresh()
{
    loadRules();
}

void MainWindow::onOverviewRefresh()
{
    m_overview->refresh();
}

void MainWindow::onOptionsChanged()
{
    applyRefreshSettings();
    loadAiModel();
}

void MainWindow::onAutoRefresh()
{
    m_overview->refresh();
    if (ui->stackedWidget->currentIndex() == 1)
        loadRules();
    else if (ui->stackedWidget->currentIndex() == 2)
        m_apps->refresh();
    else if (ui->stackedWidget->currentIndex() == 3)
        m_connections->refresh();
}

void MainWindow::loadAiModel()
{
    QSettings s(QStringLiteral("Vigil Fluminis"), QStringLiteral("Vigil Fluminis"));
    AiConfig cfg;
    cfg.modelPath = s.value(QStringLiteral("ai/modelPath")).toString();
    cfg.maxTokens = s.value(QStringLiteral("ai/maxTokens"), 1024).toInt();
    cfg.temperature = s.value(QStringLiteral("ai/temperature"), 0.3).toFloat();
    cfg.enabled = s.value(QStringLiteral("ai/enabled"), false).toBool();
    cfg.systemPrompt = s.value(QStringLiteral("ai/systemPrompt")).toString();
    AiAssistant::setConfig(cfg);
    updateAiButtonState();
}

void MainWindow::updateAiButtonState()
{
    if (m_apps)
        m_apps->updateAiButtonState();
    if (m_connections)
        m_connections->updateAiButtonState();
    if (m_askAiAction)
        m_askAiAction->setEnabled(AiAssistant::isModelLoaded());
}

void MainWindow::onAskAi()
{
    if (!AiAssistant::isModelLoaded()) {
        QMessageBox::information(this, QStringLiteral("AI Assistant"),
            QStringLiteral("No AI model loaded.\n\n"
                           "Go to Options → AI Settings to configure the model path."));
        return;
    }

    auto idx = m_proxy->mapToSource(ui->tableView->currentIndex());
    if (!idx.isValid()) {
        QMessageBox::information(this, QStringLiteral("AI Assistant"),
            QStringLiteral("Please select a firewall rule first."));
        return;
    }

    FirewallRule rule = m_model->ruleAt(idx.row());
    RiskResult risk = RiskAnalyzer::analyze(rule);

    auto dialog = new AiResultDialog(rule, risk, this);
    dialog->open();
}

void MainWindow::onAiSettings()
{
    OptionsDialog dlg(this);
    if (dlg.exec() == QDialog::Accepted)
        onOptionsChanged();
}

void MainWindow::onTableContextMenu(const QPoint &pos)
{
    auto idx = ui->tableView->indexAt(pos);
    if (!idx.isValid())
        return;

    bool hasModel = AiAssistant::isModelLoaded();
    m_askAiAction->setEnabled(hasModel);

    m_tableContextMenu->popup(ui->tableView->viewport()->mapToGlobal(pos));
}

bool MainWindow::showDangerousPortWarning(const FirewallRule &rule)
{
    QSettings s(QStringLiteral("Vigil Fluminis"), QStringLiteral("Vigil Fluminis"));
    if (!s.value(QStringLiteral("warnports/enabled"), true).toBool())
        return false;

    if (!ThreatDatabase::isRiskyRule(rule))
        return false;

    auto risks = ThreatDatabase::riskDescriptions(rule);
    QString details = QStringLiteral(
        "The following rule allows traffic on known dangerous ports:\n\n");
    for (const auto &r : risks)
        details += r + QStringLiteral("\n");
    details += QStringLiteral("\nAre you sure you want to allow this?");

    auto reply = QMessageBox::warning(
        this, QStringLiteral("Dangerous Port Warning"),
        details,
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);

    return reply != QMessageBox::Yes;
}

void MainWindow::onAddRule()
{
    RuleDialog dialog(this);
    if (dialog.exec() != QDialog::Accepted)
        return;

    FirewallRule rule = dialog.rule();

    if (showDangerousPortWarning(rule))
        return;

    QTemporaryFile tmp;
    if (!tmp.open()) {
        QMessageBox::warning(this, QStringLiteral("Error"),
            QStringLiteral("Failed to create temporary file."));
        return;
    }
    tmp.setAutoRemove(false);
    QDataStream out(&tmp);
    out << 0x02 << QString()
        << rule.name << rule.description << rule.applicationPath
        << static_cast<int>(rule.direction) << static_cast<int>(rule.action)
        << static_cast<int>(rule.protocol)
        << rule.localPorts << rule.remotePorts << rule.remoteAddresses
        << rule.enabled;
    QString tmpPath = tmp.fileName();
    tmp.close();

    Elevation::requestElevation({QStringLiteral("--add-rule"), tmpPath});
    QTimer::singleShot(1500, this, &MainWindow::onRefresh);
}

void MainWindow::onEditRule()
{
    auto idx = m_proxy->mapToSource(ui->tableView->currentIndex());
    if (!idx.isValid())
        return;

    FirewallRule rule = m_model->ruleAt(idx.row());
    RuleDialog dialog(rule, this);
    if (dialog.exec() != QDialog::Accepted)
        return;

    FirewallRule newRule = dialog.rule();
    newRule.id = rule.id;

    if (showDangerousPortWarning(newRule))
        return;

    QTemporaryFile tmp;
    if (!tmp.open()) {
        QMessageBox::warning(this, QStringLiteral("Error"),
            QStringLiteral("Failed to create temporary file."));
        return;
    }
    tmp.setAutoRemove(false);
    QDataStream out(&tmp);
    out << 0x02 << newRule.id
        << newRule.name << newRule.description
        << newRule.applicationPath << static_cast<int>(newRule.direction)
        << static_cast<int>(newRule.action) << static_cast<int>(newRule.protocol)
        << newRule.localPorts << newRule.remotePorts << newRule.remoteAddresses
        << newRule.enabled;
    QString tmpPath = tmp.fileName();
    tmp.close();

    Elevation::requestElevation({QStringLiteral("--edit-rule"), tmpPath});
    QTimer::singleShot(1500, this, &MainWindow::onRefresh);
}

void MainWindow::onDeleteRule()
{
    auto idx = m_proxy->mapToSource(ui->tableView->currentIndex());
    if (!idx.isValid())
        return;

    auto reply = QMessageBox::question(
        this, QStringLiteral("Delete Rule"),
        QStringLiteral("Are you sure you want to delete '%1'?")
            .arg(m_model->ruleAt(idx.row()).name),
        QMessageBox::Yes | QMessageBox::No);

    if (reply != QMessageBox::Yes)
        return;

    Elevation::requestElevation({
        QStringLiteral("--delete-rule"),
        m_model->ruleAt(idx.row()).id,
    });
    QTimer::singleShot(1500, this, &MainWindow::onRefresh);
}

void MainWindow::onToggleEnabled()
{
    auto idx = m_proxy->mapToSource(ui->tableView->currentIndex());
    if (!idx.isValid())
        return;

    const auto &rule = m_model->ruleAt(idx.row());
    Elevation::requestElevation({
        QStringLiteral("--set-enabled"),
        rule.id,
        rule.enabled ? QStringLiteral("0") : QStringLiteral("1"),
    });
    QTimer::singleShot(1500, this, &MainWindow::onRefresh);
}

void MainWindow::onToggleFirewall()
{
    Elevation::requestElevation({QStringLiteral("--toggle-firewall")});
    QTimer::singleShot(1500, this, &MainWindow::onOverviewRefresh);
}
