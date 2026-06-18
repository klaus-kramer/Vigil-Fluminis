// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#include "BackupManager.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QDateTime>
#include <QFileInfo>

static void ruleToJson(const FirewallRule &rule, QJsonObject &obj)
{
    obj[QStringLiteral("id")] = rule.id;
    obj[QStringLiteral("name")] = rule.name;
    obj[QStringLiteral("description")] = rule.description;
    obj[QStringLiteral("applicationPath")] = rule.applicationPath;
    obj[QStringLiteral("direction")] = static_cast<int>(rule.direction);
    obj[QStringLiteral("action")] = static_cast<int>(rule.action);
    obj[QStringLiteral("protocol")] = static_cast<int>(rule.protocol);
    obj[QStringLiteral("enabled")] = rule.enabled;

    QJsonArray localPorts;
    for (int p : rule.localPorts)
        localPorts.append(p);
    obj[QStringLiteral("localPorts")] = localPorts;

    QJsonArray remotePorts;
    for (int p : rule.remotePorts)
        remotePorts.append(p);
    obj[QStringLiteral("remotePorts")] = remotePorts;

    QJsonArray remoteAddrs;
    for (const auto &a : rule.remoteAddresses)
        remoteAddrs.append(a);
    obj[QStringLiteral("remoteAddresses")] = remoteAddrs;
}

static FirewallRule ruleFromJson(const QJsonObject &obj)
{
    FirewallRule rule;
    rule.id = obj[QStringLiteral("id")].toString();
    rule.name = obj[QStringLiteral("name")].toString();
    rule.description = obj[QStringLiteral("description")].toString();
    rule.applicationPath = obj[QStringLiteral("applicationPath")].toString();
    rule.direction = static_cast<FirewallRule::Direction>(
        obj[QStringLiteral("direction")].toInt());
    rule.action = static_cast<FirewallRule::Action>(
        obj[QStringLiteral("action")].toInt());
    rule.protocol = static_cast<FirewallRule::Protocol>(
        obj[QStringLiteral("protocol")].toInt());
    rule.enabled = obj[QStringLiteral("enabled")].toBool();

    for (const auto &v : obj[QStringLiteral("localPorts")].toArray())
        rule.localPorts.append(v.toInt());
    for (const auto &v : obj[QStringLiteral("remotePorts")].toArray())
        rule.remotePorts.append(v.toInt());
    for (const auto &v : obj[QStringLiteral("remoteAddresses")].toArray())
        rule.remoteAddresses.append(v.toString());

    return rule;
}

QString BackupManager::backupDir()
{
    QString path = QCoreApplication::applicationDirPath()
        + QStringLiteral("/backups");
    QDir dir(path);
    if (!dir.exists())
        dir.mkpath(QStringLiteral("."));
    return dir.absolutePath();
}

bool BackupManager::createBackup(const QVector<FirewallRule> &rules)
{
    QJsonArray arr;
    for (const auto &r : rules) {
        QJsonObject obj;
        ruleToJson(r, obj);
        arr.append(obj);
    }

    QJsonObject root;
    root[QStringLiteral("version")] = 1;
    root[QStringLiteral("count")] = rules.size();
    root[QStringLiteral("rules")] = arr;

    QString ts = QDateTime::currentDateTime().toString(
        QStringLiteral("yyyyMMdd_HHmmss"));
    QString fileName = backupDir()
        + QStringLiteral("/Vigil Fluminis_backup_")
        + ts + QStringLiteral(".json");

    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly))
        return false;

    file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    return true;
}

QVector<FirewallRule> BackupManager::loadBackup(const QString &filePath)
{
    QVector<FirewallRule> result;

    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly))
        return result;

    QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    if (doc.isNull() || !doc.isObject())
        return result;

    QJsonObject root = doc.object();
    QJsonArray arr = root[QStringLiteral("rules")].toArray();

    for (const auto &v : arr) {
        if (v.isObject())
            result.append(ruleFromJson(v.toObject()));
    }

    return result;
}

QStringList BackupManager::listBackups()
{
    QDir dir(backupDir());
    QStringList filters;
    filters << QStringLiteral("Vigil Fluminis_backup_*.json");
    QStringList entries = dir.entryList(filters, QDir::Files, QDir::Time);
    QStringList fullPaths;
    for (const auto &e : entries)
        fullPaths.append(dir.absoluteFilePath(e));
    return fullPaths;
}

QString BackupManager::latestBackup()
{
    QStringList backups = listBackups();
    return backups.isEmpty() ? QString() : backups.first();
}
