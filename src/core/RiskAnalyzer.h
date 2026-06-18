// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#pragma once

#include "FirewallRule.h"
#include <QColor>
#include <QString>
#include <QStringList>

struct RiskResult
{
    enum Level { Safe, Low, Medium, High, Critical };

    Level level = Safe;
    int score = 0;
    QStringList details;

    bool isRisky() const { return level >= Medium; }
    QColor backgroundColor() const;
    QString levelText() const;

    QString ipRepText;
    QString ipRepTooltip;
};

class RiskAnalyzer
{
public:
    static RiskResult analyze(const FirewallRule &rule);

    static QString suspiciousPathInfo(const QString &appPath);

    static QString suspiciousFileAgeInfo(const QString &appPath);

    static QString permissiveRuleInfo(const FirewallRule &rule);
};
