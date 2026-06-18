// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#include "RiskAnalyzer.h"
#include "ThreatDatabase.h"
#include "IpReputationDb.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QStandardPaths>

QColor RiskResult::backgroundColor() const
{
    switch (level) {
    case Safe:     return QColor();
    case Low:      return QColor(255, 248, 220);
    case Medium:   return QColor(255, 235, 160);
    case High:     return QColor(255, 200, 100);
    case Critical: return QColor(255, 160, 100);
    }
    return {};
}

QString RiskResult::levelText() const
{
    switch (level) {
    case Safe:     return QString();
    case Low:      return QStringLiteral("Low");
    case Medium:   return QStringLiteral("Medium");
    case High:     return QStringLiteral("High");
    case Critical: return QStringLiteral("Critical");
    }
    return {};
}

QString RiskAnalyzer::suspiciousPathInfo(const QString &appPath)
{
    if (appPath.isEmpty())
        return {};

    QString lower = appPath.toLower();

    QString tmp = QDir::tempPath().toLower();
    if (!tmp.isEmpty() && lower.startsWith(tmp))
        return QStringLiteral("Runs from Temp directory");

    QString downloads = QStandardPaths::writableLocation(
        QStandardPaths::DownloadLocation).toLower();
    if (!downloads.isEmpty() && lower.startsWith(downloads))
        return QStringLiteral("Runs from Downloads");

    QString appData = QStandardPaths::writableLocation(
        QStandardPaths::AppLocalDataLocation).toLower();
    if (!appData.isEmpty() && lower.startsWith(appData))
        return QStringLiteral("Runs from AppData (Local)");

    QString roaming = QStandardPaths::writableLocation(
        QStandardPaths::GenericDataLocation).toLower();
    if (!roaming.isEmpty() && lower.startsWith(roaming))
        return QStringLiteral("Runs from AppData (Roaming)");

    return {};
}

QString RiskAnalyzer::suspiciousFileAgeInfo(const QString &appPath)
{
    if (appPath.isEmpty())
        return {};

    QFileInfo fi(appPath);
    if (!fi.exists())
        return {};

    QDateTime mod = fi.lastModified();
    if (!mod.isValid())
        return {};

    qint64 days = mod.daysTo(QDateTime::currentDateTime());

    if (days < 15)
        return QStringLiteral("File created less than 15 days ago");
    if (days > 1460)
        return QStringLiteral("File older than 4 years");

    return {};
}

QString RiskAnalyzer::permissiveRuleInfo(const FirewallRule &rule)
{
    if (rule.action != FirewallRule::Action::Allow)
        return {};

    QStringList reasons;

    if (rule.remoteAddresses.isEmpty() ||
        rule.remoteAddresses.contains(QStringLiteral("*")) ||
        rule.remoteAddresses.contains(QStringLiteral("any")))
        reasons.append(QStringLiteral("Any remote address"));

    if (rule.remotePorts.isEmpty())
        reasons.append(QStringLiteral("Any remote port"));

    if (rule.protocol == FirewallRule::Protocol::Any)
        reasons.append(QStringLiteral("Any protocol"));

    if (rule.applicationPath.isEmpty())
        reasons.append(QStringLiteral("No app restriction"));

    if (rule.direction == FirewallRule::Direction::Outbound &&
        rule.applicationPath.isEmpty())
        reasons.append(QStringLiteral("Outbound + no app restriction"));

    return reasons.isEmpty() ? QString() : reasons.join(QStringLiteral(", "));
}

static bool isSuspiciousPath(const QString &appPath)
{
    return !RiskAnalyzer::suspiciousPathInfo(appPath).isEmpty();
}

RiskResult RiskAnalyzer::analyze(const FirewallRule &rule)
{
    RiskResult result;

    if (rule.action != FirewallRule::Action::Allow)
        return result;

    if (ThreatDatabase::isRiskyRule(rule)) {
        result.score += 3;
        auto risks = ThreatDatabase::riskDescriptions(rule);
        for (const auto &r : risks)
            result.details.append(r);
    }

    if (rule.applicationPath.isEmpty()) {
        result.score += 2;
        result.details.append(QStringLiteral("No application path - applies to all executables"));
    } else {
        if (isSuspiciousPath(rule.applicationPath)) {
            result.score += 2;
            result.details.append(QStringLiteral("Application runs from a user-writable directory")
                + QStringLiteral(" (%1)").arg(QDir::toNativeSeparators(rule.applicationPath)));
        }

        QString ageInfo = suspiciousFileAgeInfo(rule.applicationPath);
        if (!ageInfo.isEmpty()) {
            result.score += 1;
            result.details.append(ageInfo);
        }
    }

    if (rule.action == FirewallRule::Action::Allow && !rule.remoteAddresses.isEmpty()) {
        bool hasSuspicious = false;
        bool hasSafe = false;
        QStringList labels;
        for (const auto &addr : rule.remoteAddresses) {
            if (addr == QStringLiteral("*") || addr == QStringLiteral("any"))
                continue;
            auto ipRes = IpReputationDb::checkIp(addr);
            if (ipRes.status == IpReputationResult::Suspicious) {
                hasSuspicious = true;
                labels.append(ipRes.label);
            } else if (ipRes.status == IpReputationResult::Safe) {
                hasSafe = true;
            }
        }
        if (hasSuspicious) {
            result.score += 3;
            result.details.append(QStringLiteral("Remote address known suspicious: %1")
                .arg(labels.join(QStringLiteral(", "))));
            result.ipRepText = QStringLiteral("Suspicious");
            result.ipRepTooltip = labels.join(QStringLiteral(", "));
        } else if (hasSafe) {
            result.ipRepText = QStringLiteral("Safe");
            result.ipRepTooltip = QStringLiteral("Known safe address");
        } else {
            result.ipRepText = QStringLiteral("Unknown");
        }
    } else {
        result.ipRepText = QStringLiteral("Unknown");
    }

    QString permissive = permissiveRuleInfo(rule);
    if (!permissive.isEmpty()) {
        int points = 0;
        if (rule.remoteAddresses.isEmpty() || rule.remoteAddresses.contains(QStringLiteral("*")) || rule.remoteAddresses.contains(QStringLiteral("any")))
            ++points;
        if (rule.remotePorts.isEmpty())
            ++points;
        if (rule.protocol == FirewallRule::Protocol::Any)
            ++points;
        if (rule.applicationPath.isEmpty())
            ++points;
        if (rule.direction == FirewallRule::Direction::Outbound && rule.applicationPath.isEmpty())
            ++points;
        result.score += points;
        result.details.append(QStringLiteral("Overly permissive: %1").arg(permissive));
    }

    if (result.score >= 6)
        result.level = RiskResult::Critical;
    else if (result.score >= 4)
        result.level = RiskResult::High;
    else if (result.score >= 2)
        result.level = RiskResult::Medium;
    else if (result.score >= 1)
        result.level = RiskResult::Low;

    return result;
}
