// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#pragma once

#include <QString>
#include <QVector>

struct IpReputationEntry
{
    quint32 baseAddr = 0;
    quint32 mask = 0;
    QString cidr;
    QString label;
    bool isSafe = false;
};

struct IpReputationResult
{
    enum Status { Unknown, Safe, Suspicious };
    Status status = Unknown;
    QString label;
};

class IpReputationDb
{
public:
    static IpReputationResult checkIp(const QString &ip);

private:
    static void ensureLoaded();
    static void writeDefaults(const QString &path);

    static QVector<IpReputationEntry> s_entries;
    static bool s_loaded;
};
