// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#pragma once

#include <QWidget>
#include <QStringList>
#include <QList>

class QLabel;
class QPushButton;
class IFirewall;

class OverviewWidget : public QWidget
{
    Q_OBJECT

public:
    explicit OverviewWidget(IFirewall *firewall, QWidget *parent = nullptr);

    void refresh();
    void setTopSuspiciousApps(const QStringList &names, const QList<int> &scores);

signals:
    void manageRulesClicked();
    void manageAppsClicked();
    void manageConnectionsClicked();
    void optionsChanged();
    void aiSettingsClicked();

private:
    void setupUi();

    IFirewall *m_firewall = nullptr;

    QPushButton *m_firewallToggle = nullptr;
    QLabel *m_statusLabel = nullptr;
    QLabel *m_serviceStatusLabel = nullptr;
    QPushButton *m_serviceToggle = nullptr;
    QLabel *m_totalRulesLabel = nullptr;
    QLabel *m_allowedLabel = nullptr;
    QLabel *m_blockedLabel = nullptr;
    QLabel *m_enabledLabel = nullptr;
    QLabel *m_disabledLabel = nullptr;
    QLabel *m_riskyRulesLabel = nullptr;

    QLabel *m_suspiciousTitleLabel = nullptr;
    QLabel *m_suspiciousNames[3] = {};
    QLabel *m_suspiciousScores[3] = {};
};
