// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#include "ThreatDatabase.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>

QVector<DangerousPort> ThreatDatabase::s_ports;
bool ThreatDatabase::s_loaded = false;

static const DangerousPort s_defaultPorts[] = {
    { 21,    "FTP",       "Unencrypted file transfer – credentials and data in plaintext.",                                            "Replace FTP with SFTP (port 22) or FTPS." },
    { 23,    "Telnet",    "Plaintext remote access – transmits credentials in clear text.",                                            "Telnet is obsolete. Use SSH (port 22) instead." },
    { 25,    "SMTP",      "Unencrypted email – potential spam relay and phishing vector.",                                             "Only open if you run a mail server. Otherwise block." },
    { 135,   "RPC",       "Windows RPC – frequently targeted for remote exploitation.",                                               "Do not expose to the internet. Only needed in Windows domains on LAN." },
    { 137,   "NetBIOS",   "NetBIOS Name Service – legacy protocol, common attack surface.",                                           "Block on internet-facing interfaces. Legacy protocol – disable if possible." },
    { 138,   "NetBIOS",   "NetBIOS Datagram Service – legacy protocol.",                                                              "Block on internet-facing interfaces. Legacy protocol – disable if possible." },
    { 139,   "NetBIOS",   "NetBIOS Session Service – legacy protocol, SMB vector.",                                                   "Block on internet-facing interfaces. Use SMB over port 445 only." },
    { 445,   "SMB",       "Windows file sharing – major ransomware vector (EternalBlue).",                                            "Only open in trusted local networks. Never expose SMB to the internet." },
    { 1433,  "MSSQL",     "Microsoft SQL Server – database targeted by brute force.",                                                 "Restrict to trusted client IPs. Use VPN for remote access." },
    { 1434,  "MSSQL",     "Microsoft SQL Server monitor – scanning target.",                                                          "Do not expose publicly. Restrict to trusted clients." },
    { 3306,  "MySQL",     "MySQL database – common brute-force target.",                                                              "Do not make MySQL publicly accessible. Use localhost or VPN." },
    { 3389,  "RDP",       "Remote Desktop – most common brute-force target.",                                                         "Only use RDP via VPN, or restrict to known IP addresses." },
    { 5900,  "VNC",       "Virtual Network Computing – outdated encryption.",                                                         "Replace VNC with RDP or use an SSH tunnel." },
    { 6379,  "Redis",     "Redis – often exploited when exposed without authentication.",                                             "Redis must not be exposed to the internet. Enable authentication." },
    { 27017, "MongoDB",   "MongoDB – frequently targeted when exposed to the internet.",                                              "Do not expose MongoDB publicly. Enable authentication and IP whitelisting." },
};
static const int s_defaultCount = sizeof(s_defaultPorts) / sizeof(s_defaultPorts[0]);

void ThreatDatabase::writeDefaults(const QString &path)
{
    QJsonArray arr;
    for (int i = 0; i < s_defaultCount; ++i) {
        QJsonObject obj;
        obj[QStringLiteral("port")] = s_defaultPorts[i].port;
        obj[QStringLiteral("service")] = s_defaultPorts[i].service;
        obj[QStringLiteral("risk")] = s_defaultPorts[i].risk;
        obj[QStringLiteral("recommendation")] = s_defaultPorts[i].recommendation;
        arr.append(obj);
    }

    QFile file(path);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        file.write(QJsonDocument(arr).toJson(QJsonDocument::Indented));
    }
}

void ThreatDatabase::ensureLoaded()
{
    if (s_loaded)
        return;
    s_loaded = true;

    QString path = QCoreApplication::applicationDirPath()
        + QStringLiteral("/threats.json");

    QFile file(path);
    if (file.open(QIODevice::ReadOnly)) {
        QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
        file.close();
        if (doc.isArray()) {
            for (const auto &val : doc.array()) {
                QJsonObject obj = val.toObject();
                DangerousPort p;
                p.port = obj[QStringLiteral("port")].toInt();
                p.service = obj[QStringLiteral("service")].toString();
                p.risk = obj[QStringLiteral("risk")].toString();
                p.recommendation = obj[QStringLiteral("recommendation")].toString();
                s_ports.append(p);
            }
            return;
        }
    }

    writeDefaults(path);

    for (int i = 0; i < s_defaultCount; ++i)
        s_ports.append(s_defaultPorts[i]);
}

bool ThreatDatabase::isRiskyRule(const FirewallRule &rule)
{
    ensureLoaded();

    if (rule.action != FirewallRule::Action::Allow)
        return false;

    auto portMatches = [](const QVector<int> &ports) {
        for (int p : ports) {
            for (const auto &dp : s_ports) {
                if (p == dp.port)
                    return true;
            }
        }
        return false;
    };

    if (portMatches(rule.localPorts))
        return true;
    if (portMatches(rule.remotePorts))
        return true;

    return false;
}

bool ThreatDatabase::isPortDangerous(int port)
{
    ensureLoaded();
    for (const auto &dp : s_ports) {
        if (port == dp.port)
            return true;
    }
    return false;
}

QVector<QString> ThreatDatabase::riskDescriptions(const FirewallRule &rule)
{
    ensureLoaded();

    QVector<QString> result;

    if (rule.action != FirewallRule::Action::Allow)
        return result;

    auto checkPorts = [&](const QVector<int> &ports, const char *direction) {
        for (int p : ports) {
            for (const auto &dp : s_ports) {
                if (p == dp.port) {
                    result.append(QStringLiteral("[%1] Port %2 (%3): %4\n\u279c Recommendation: %5")
                        .arg(QString::fromUtf8(direction))
                        .arg(p)
                        .arg(dp.service)
                        .arg(dp.risk)
                        .arg(dp.recommendation));
                }
            }
        }
    };

    checkPorts(rule.localPorts, "Local");
    checkPorts(rule.remotePorts, "Remote");

    return result;
}
