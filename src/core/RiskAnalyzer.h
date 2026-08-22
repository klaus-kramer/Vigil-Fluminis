// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#pragma once

#include "FirewallRule.h"
#include "FileAnalyzer.h"
#include "SignatureChecker.h"
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
    enum class Sensitivity { Relaxed = 0, Balanced = 1, Strict = 2 };

    static RiskResult analyze(const FirewallRule &rule);

    static void setSensitivity(Sensitivity s);
    static Sensitivity sensitivity();
    static void loadSettings();

    static QString suspiciousPathInfo(const QString &appPath);

    static QString suspiciousFileAgeInfo(const QString &appPath);

    static QString permissiveRuleInfo(const FirewallRule &rule);

private:
    struct BinaryTrust
    {
        bool trusted = false;
        bool knownPublisher = false;
        QString publisher;
    };

    static BinaryTrust binaryTrust(const QString &appPath);

    static Sensitivity s_sensitivity;
};
