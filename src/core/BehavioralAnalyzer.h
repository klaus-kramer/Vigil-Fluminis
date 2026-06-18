// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#pragma once

#include <QSet>
#include <QMap>
#include <QString>
#include <QVector>
#include <QPair>

struct ConnectionKey {
    quint32 pid = 0;
    QString remoteAddr;
    int remotePort = 0;

    bool operator==(const ConnectionKey &o) const;
    bool operator!=(const ConnectionKey &o) const;
    uint qHash(const ConnectionKey &k, uint seed = 0);
};

struct ConnectionSnapshot {
    QSet<ConnectionKey> connections;
    QMap<quint32, QString> processNames;
};

struct NewConnectionInfo {
    quint32 pid = 0;
    QString processName;
    QString processPath;
    QVector<QPair<QString, int>> newEndpoints;
};

struct ByteScanRecord {
    quint32 pid = 0;
    quint64 bytesOut = 0;
    quint64 bytesIn = 0;
    QString remoteAddr;
    int remotePort = 0;
};

class BehavioralAnalyzer
{
public:
    static ConnectionSnapshot takeSnapshot();
    static QVector<NewConnectionInfo> compare(
        const ConnectionSnapshot &before,
        const ConnectionSnapshot &after);

    static QVector<ByteScanRecord> takeSnapshotWithBytes();
    static QVector<NewConnectionInfo> compareBytes(
        const QVector<ByteScanRecord> &before,
        const QVector<ByteScanRecord> &after);

    static QSet<quint32> activePidsBetween(
        const QVector<ByteScanRecord> &prev,
        const QVector<ByteScanRecord> &curr);
};
