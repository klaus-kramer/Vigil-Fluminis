// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#pragma once

#include <QWidget>
#include <QVector>
#include "core/ConnectionInfo.h"
#include "core/KnownMalwareDb.h"
#include "core/SignatureChecker.h"
#include "core/FileAnalyzer.h"

class QTableWidget;
class QTableWidgetItem;
class QLabel;
class QPushButton;

class ConnectionsWidget : public QWidget
{
    Q_OBJECT

public:
    explicit ConnectionsWidget(QWidget *parent = nullptr);

    void refresh();
    void updateAiButtonState();

signals:
    void backToOverview();
    void connStatsUpdated(int total, int suspiciousCount);

private:
    void setupUi();
    void onAskAi();
    void onTableContextMenu(const QPoint &pos);
    void updateSuspiciousRow(int row, const ConnectionInfo &conn);
    QString suspiciousTooltip(const ConnectionInfo &conn) const;

    QTableWidget *m_table = nullptr;
    QLabel *m_statusLabel = nullptr;
    QPushButton *m_askAiBtn = nullptr;
};
