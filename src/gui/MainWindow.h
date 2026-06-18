// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#pragma once

#include <QMainWindow>
#include <QVector>
#include <memory>

struct FirewallRule;
struct RiskResult;
class FirewallManager;
class QStackedWidget;
class QTableView;
class QSortFilterProxyModel;
class QLabel;
class QPushButton;
class QToolBar;
class QAction;
class QLineEdit;
class QStatusBar;
class QTimer;
class QMenu;

class OverviewWidget;
class AppsWidget;
class ConnectionsWidget;
class RuleTableModel;
class FirewallManager;
class IFirewall;

namespace Ui { class MainWindow; }

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(std::unique_ptr<FirewallManager> manager);
    ~MainWindow() override;

private:
    void setupUi();
    void applyRefreshSettings();
    void loadRules();
    void updateStatusBar();
    bool showDangerousPortWarning(const FirewallRule &rule);
    void loadAiModel();
    void updateAiButtonState();

    std::unique_ptr<Ui::MainWindow> ui;

    std::unique_ptr<FirewallManager> m_manager;
    IFirewall *m_firewall = nullptr;

    OverviewWidget *m_overview = nullptr;
    AppsWidget *m_apps = nullptr;
    ConnectionsWidget *m_connections = nullptr;

    RuleTableModel *m_model = nullptr;
    QSortFilterProxyModel *m_proxy = nullptr;

    QAction *m_refreshAction = nullptr;
    QAction *m_addAction = nullptr;
    QAction *m_editAction = nullptr;
    QAction *m_deleteAction = nullptr;
    QAction *m_toggleEnabledAction = nullptr;
    QAction *m_riskyOnlyAction = nullptr;
    QAction *m_askAiAction = nullptr;

    QMenu *m_tableContextMenu = nullptr;

    QTimer *m_refreshTimer = nullptr;

    bool m_backedUp = false;

private slots:
    void showOverview();
    void showRules();
    void showApps();
    void showConnections();
    void showRulesForApp(const QString &appPath);
    void onRefresh();
    void onAddRule();
    void onEditRule();
    void onDeleteRule();
    void onToggleEnabled();
    void onToggleFirewall();
    void onOverviewRefresh();
    void onOptionsChanged();
    void onAutoRefresh();
    void onAskAi();
    void onAiSettings();
    void onTableContextMenu(const QPoint &pos);
};
