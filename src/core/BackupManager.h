// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#pragma once

#include "FirewallRule.h"
#include <QString>
#include <QVector>
#include <QStringList>

class BackupManager {
public:
    static QString backupDir();

    static bool createBackup(const QVector<FirewallRule> &rules);

    static QVector<FirewallRule> loadBackup(const QString &filePath);

    static QStringList listBackups();

    static QString latestBackup();
};
