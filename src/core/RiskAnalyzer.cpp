// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#include "RiskAnalyzer.h"
#include "ThreatDatabase.h"
#include "IpReputationDb.h"

#include <QDir>
#include <QFileInfo>
#include <QHash>
#include <QSettings>
#include <QStandardPaths>

RiskAnalyzer::Sensitivity RiskAnalyzer::s_sensitivity = Sensitivity::Balanced;

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

void RiskAnalyzer::setSensitivity(Sensitivity s)
{
    s_sensitivity = s;
}

RiskAnalyzer::Sensitivity RiskAnalyzer::sensitivity()
{
    return s_sensitivity;
}

void RiskAnalyzer::loadSettings()
{
    QSettings settings(QStringLiteral("Vigil Fluminis"), QStringLiteral("Vigil Fluminis"));
    int value = settings.value(QStringLiteral("scoring/sensitivity"),
        static_cast<int>(Sensitivity::Balanced)).toInt();
    if (value < static_cast<int>(Sensitivity::Relaxed) ||
        value > static_cast<int>(Sensitivity::Strict))
        value = static_cast<int>(Sensitivity::Balanced);
    s_sensitivity = static_cast<Sensitivity>(value);
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

    return reasons.isEmpty() ? QString() : reasons.join(QStringLiteral(", "));
}

RiskAnalyzer::BinaryTrust RiskAnalyzer::binaryTrust(const QString &appPath)
{
    static QHash<QString, BinaryTrust> cache;

    auto it = cache.constFind(appPath);
    if (it != cache.constEnd())
        return it.value();

    BinaryTrust info;

    SignatureResult sig = SignatureChecker::check(appPath);
    info.trusted = sig.isTrusted();
    info.publisher = sig.publisher;

    if (!info.trusted) {
        FileInfoResult fi = FileAnalyzer::analyze(appPath);
        info.knownPublisher = FileAnalyzer::isKnownPublisher(fi.companyName);
    }

    cache.insert(appPath, info);
    return info;
}

namespace {

int permissiveCriteriaCount(const FirewallRule &rule)
{
    int criteria = 0;

    if (rule.remoteAddresses.isEmpty() ||
        rule.remoteAddresses.contains(QStringLiteral("*")) ||
        rule.remoteAddresses.contains(QStringLiteral("any")))
        ++criteria;

    if (rule.remotePorts.isEmpty())
        ++criteria;

    if (rule.protocol == FirewallRule::Protocol::Any)
        ++criteria;

    return criteria;
}

} // namespace

RiskResult RiskAnalyzer::analyze(const FirewallRule &rule)
{
    RiskResult result;

    if (!rule.enabled)
        return result;

    if (rule.action != FirewallRule::Action::Allow)
        return result;

    const bool inbound = rule.direction == FirewallRule::Direction::Inbound;

    const int portPoints = ThreatDatabase::riskyPortPoints(rule);
    if (portPoints > 0) {
        result.score += portPoints;
        for (const auto &r : ThreatDatabase::riskDescriptions(rule))
            result.details.append(r);
    }

    if (rule.applicationPath.isEmpty()) {
        result.score += 2;
        result.details.append(
            QStringLiteral("No application path - applies to all executables"));
    } else {
        const bool pathSuspicious = !suspiciousPathInfo(rule.applicationPath).isEmpty();

        BinaryTrust trust;
        bool haveTrust = false;

        if (pathSuspicious) {
            trust = binaryTrust(rule.applicationPath);
            haveTrust = true;

            if (trust.trusted) {
                result.details.append(QStringLiteral("Digitally signed (%1)")
                    .arg(trust.publisher.isEmpty()
                        ? QStringLiteral("verified publisher")
                        : trust.publisher));
            } else {
                result.score += 2;
                result.details.append(
                    QStringLiteral("Application runs from a user-writable directory")
                    + QStringLiteral(" (%1)")
                          .arg(QDir::toNativeSeparators(rule.applicationPath)));
            }
        }

        if (result.score > 0) {
            QString ageInfo = suspiciousFileAgeInfo(rule.applicationPath);
            if (!ageInfo.isEmpty()) {
                if (!haveTrust) {
                    trust = binaryTrust(rule.applicationPath);
                    haveTrust = true;
                    if (trust.trusted) {
                        result.details.append(QStringLiteral("Digitally signed (%1)")
                            .arg(trust.publisher.isEmpty()
                                ? QStringLiteral("verified publisher")
                                : trust.publisher));
                    }
                }
                if (!(trust.trusted || trust.knownPublisher)) {
                    result.score += 1;
                    result.details.append(ageInfo);
                }
            }
        }
    }

    if (!rule.remoteAddresses.isEmpty()) {
        QStringList strongLabels;
        QStringList weakLabels;
        bool hasSafe = false;

        for (const auto &addr : rule.remoteAddresses) {
            if (addr == QStringLiteral("*") || addr == QStringLiteral("any"))
                continue;
            auto ipRes = IpReputationDb::checkIp(addr);
            switch (ipRes.status) {
            case IpReputationResult::Suspicious:
                strongLabels.append(ipRes.label);
                break;
            case IpReputationResult::Weak:
                weakLabels.append(ipRes.label);
                break;
            case IpReputationResult::Safe:
                hasSafe = true;
                break;
            default:
                break;
            }
        }

        if (!strongLabels.isEmpty()) {
            result.score += 3;
            result.details.append(QStringLiteral("Remote address known suspicious: %1")
                .arg(strongLabels.join(QStringLiteral(", "))));
            result.ipRepText = QStringLiteral("Suspicious");
            result.ipRepTooltip = strongLabels.join(QStringLiteral(", "));
        } else if (!weakLabels.isEmpty()) {
            result.score += 1;
            result.details.append(
                QStringLiteral("Remote address in hosting-provider range (weak signal): %1")
                    .arg(weakLabels.join(QStringLiteral(", "))));
            result.ipRepText = QStringLiteral("Weak");
            result.ipRepTooltip = weakLabels.join(QStringLiteral(", "));
        } else if (hasSafe) {
            result.ipRepText = QStringLiteral("Safe");
            result.ipRepTooltip = QStringLiteral("Known safe address");
        } else {
            result.ipRepText = QStringLiteral("Unknown");
        }
    } else {
        result.ipRepText = QStringLiteral("Unknown");
    }

    const int criteria = permissiveCriteriaCount(rule);
    if (criteria > 0) {
        int points = inbound ? qMin(criteria, 3) : qMin(criteria, 1);
        if (inbound && (rule.profiles & FirewallRule::ProfilePublic))
            ++points;
        result.score += points;
        result.details.append(QStringLiteral("Overly permissive: %1")
            .arg(permissiveRuleInfo(rule)));
    }

    if ((rule.profiles & FirewallRule::ProfilePublic) == 0 && result.score > 0) {
        --result.score;
        result.details.append(QStringLiteral("Restricted to Domain/Private profile"));
    }

    int mediumAt = 3;
    int highAt = 5;
    int criticalAt = 8;
    switch (s_sensitivity) {
    case Sensitivity::Relaxed:
        mediumAt = 4; highAt = 6; criticalAt = 9;
        break;
    case Sensitivity::Strict:
        mediumAt = 2; highAt = 4; criticalAt = 6;
        break;
    case Sensitivity::Balanced:
        break;
    }

    if (result.score >= criticalAt)
        result.level = RiskResult::Critical;
    else if (result.score >= highAt)
        result.level = RiskResult::High;
    else if (result.score >= mediumAt)
        result.level = RiskResult::Medium;
    else if (result.score >= 1)
        result.level = RiskResult::Low;

    return result;
}
