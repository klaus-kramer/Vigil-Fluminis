// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#pragma once

#include <QWidget>
#include <QVector>
#include <QHash>
#include "core/FirewallRule.h"
#include "core/KnownMalwareDb.h"
#include "core/SignatureChecker.h"
#include "core/FileAnalyzer.h"

class QTableWidget;
class QTableWidgetItem;
class QLabel;
class QPushButton;
class IFirewall;

class AppsWidget : public QWidget
{
    Q_OBJECT

public:
    explicit AppsWidget(IFirewall *firewall, QWidget *parent = nullptr);
    ~AppsWidget() override;

    void refresh();
    void updateAiButtonState();

signals:
    void showRulesForApp(const QString &appPath);
    void backToOverview();
    void topSuspiciousAppsUpdated(const QStringList &names, const QList<int> &scores);

private:
    struct AppInfo {
        QString path;
        QString name;
        int total = 0;
        int allow = 0;
        int block = 0;
        MalwareResult repResult;
        SignatureResult sigResult;
        FileInfoResult fileInfo;
        QString dirInfo;
        QString permissiveInfo;
    };

    void setupUi();
    void checkAllApps();
    void checkAllSignatures();
    void onAskAi();
    void onTableContextMenu(const QPoint &pos);
    void applyRepToItem(QTableWidgetItem *item, const MalwareResult &res);
    void applySigToItem(QTableWidgetItem *item, const SignatureResult &res);
    void applyDirToItem(QTableWidgetItem *item, const QString &dirInfo);
    void applyAgeToItem(QTableWidgetItem *item, const FileInfoResult &fi);
    void applyPermissiveToItem(QTableWidgetItem *item, const QString &permissiveInfo);
    void applyCompanyToItem(QTableWidgetItem *item, const FileInfoResult &fi);
    void applyOrigFileToItem(QTableWidgetItem *item, const AppInfo &app);
    void applyKnownPubToItem(QTableWidgetItem *item, const SignatureResult &sig);
    QString suspiciousTooltip(const AppInfo &app) const;
    void updateSuspiciousRow(int row, const AppInfo &app);
    void computeTopSuspiciousApps();
    static int suspiciousScore(const AppInfo &app);

    QVector<AppInfo> buildAppList(const QVector<FirewallRule> &rules);

    IFirewall *m_firewall = nullptr;
    QTableWidget *m_table = nullptr;
    QLabel *m_statusLabel = nullptr;
    QPushButton *m_checkRepBtn = nullptr;
    QPushButton *m_checkSigBtn = nullptr;
    QPushButton *m_askAiBtn = nullptr;
    QHash<QString, MalwareResult> m_repCache;
    QHash<QString, SignatureResult> m_sigCache;
    QHash<QString, FileInfoResult> m_fileInfoCache;
};
