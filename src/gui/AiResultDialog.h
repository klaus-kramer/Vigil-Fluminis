// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#pragma once

#include <QDialog>
#include "core/FirewallRule.h"
#include "core/RiskAnalyzer.h"

class QTextBrowser;
class QPushButton;
class QLabel;

class AiResultDialog : public QDialog
{
    Q_OBJECT

public:
    explicit AiResultDialog(const FirewallRule &rule, const RiskResult &risk,
                            QWidget *parent = nullptr);

private slots:
    void onCopy();
    void onAskAgain();
    void onResultReady(const QString &answer, qint64 ms);
    void onError(const QString &error);

private:
    void setupUi();
    void runInference();

    FirewallRule m_rule;
    RiskResult m_risk;

    QTextBrowser *m_textBrowser = nullptr;
    QPushButton *m_copyBtn = nullptr;
    QPushButton *m_againBtn = nullptr;
    QLabel *m_statusLabel = nullptr;
};
