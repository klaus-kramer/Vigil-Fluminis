// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#include "BehavioralAnalyzer.h"
#include "KnownMalwareDb.h"
#include "IpReputationDb.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tcpestats.h>
#include <windows.h>
#include <psapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

bool ConnectionKey::operator==(const ConnectionKey &o) const
{
    return pid == o.pid && remoteAddr == o.remoteAddr && remotePort == o.remotePort;
}

bool ConnectionKey::operator!=(const ConnectionKey &o) const
{
    return !(*this == o);
}

uint qHash(const ConnectionKey &k, uint seed)
{
    return qHash(k.pid) ^ qHash(k.remoteAddr, seed) ^ qHash(k.remotePort);
}

static QString addrToString(DWORD addr)
{
    IN_ADDR ia;
    ia.S_un.S_addr = addr;
    wchar_t buf[INET_ADDRSTRLEN];
    InetNtopW(AF_INET, &ia, buf, INET_ADDRSTRLEN);
    return QString::fromWCharArray(buf);
}

static QString processPathFromPid(DWORD pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h)
        return {};

    wchar_t buf[MAX_PATH];
    DWORD size = MAX_PATH;
    QString result;
    if (QueryFullProcessImageNameW(h, 0, buf, &size))
        result = QString::fromWCharArray(buf, size);
    CloseHandle(h);
    return result;
}

static void appendTcpConns(QSet<ConnectionKey> &keys, QMap<quint32, QString> &names)
{
    ULONG size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0)
        return;

    QByteArray buf(size, Qt::Uninitialized);
    auto *table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID *>(buf.data());

    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
        return;

    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto &row = table->table[i];

        ConnectionKey k;
        k.pid = row.dwOwningPid;
        k.remoteAddr = addrToString(row.dwRemoteAddr);
        k.remotePort = ntohs(static_cast<u_short>(row.dwRemotePort));
        keys.insert(k);

        if (!names.contains(k.pid)) {
            QString path = processPathFromPid(k.pid);
            if (!path.isEmpty()) {
                int idx = path.lastIndexOf('\\');
                names[k.pid] = (idx >= 0) ? path.mid(idx + 1) : path;
            }
        }
    }
}

static void appendUdpConns(QSet<ConnectionKey> &keys, QMap<quint32, QString> &names)
{
    ULONG size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (size == 0)
        return;

    QByteArray buf(size, Qt::Uninitialized);
    auto *table = reinterpret_cast<MIB_UDPTABLE_OWNER_PID *>(buf.data());

    if (GetExtendedUdpTable(table, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != NO_ERROR)
        return;

    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto &row = table->table[i];

        ConnectionKey k;
        k.pid = row.dwOwningPid;
        k.remoteAddr = addrToString(row.dwLocalAddr);
        k.remotePort = 0;
        keys.insert(k);

        if (!names.contains(k.pid)) {
            QString path = processPathFromPid(k.pid);
            if (!path.isEmpty()) {
                int idx = path.lastIndexOf('\\');
                names[k.pid] = (idx >= 0) ? path.mid(idx + 1) : path;
            }
        }
    }
}

ConnectionSnapshot BehavioralAnalyzer::takeSnapshot()
{
    ConnectionSnapshot snap;
    appendTcpConns(snap.connections, snap.processNames);
    appendUdpConns(snap.connections, snap.processNames);
    return snap;
}

QVector<NewConnectionInfo> BehavioralAnalyzer::compare(
    const ConnectionSnapshot &before,
    const ConnectionSnapshot &after)
{
    QSet<ConnectionKey> newSet = after.connections - before.connections;
    if (newSet.isEmpty())
        return {};

    QMap<quint32, NewConnectionInfo> pidMap;

    for (const auto &k : newSet) {
        NewConnectionInfo &info = pidMap[k.pid];
        info.pid = k.pid;
        info.newEndpoints.append({k.remoteAddr, k.remotePort});
    }

    for (auto it = pidMap.begin(); it != pidMap.end(); ++it) {
        NewConnectionInfo &info = it.value();
        info.processName = after.processNames.value(info.pid);
        info.processPath = processPathFromPid(info.pid);
    }

    QVector<NewConnectionInfo> result;
    for (auto it = pidMap.begin(); it != pidMap.end(); ++it)
        result.append(it.value());

    return result;
}

static void appendTcpByteRecords(QVector<ByteScanRecord> &records)
{
    ULONG size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0)
        return;

    QByteArray buf(size, Qt::Uninitialized);
    auto *table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID *>(buf.data());

    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
        return;

    QSet<QPair<DWORD, DWORD>> listeners;
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto &row = table->table[i];
        if (row.dwState == MIB_TCP_STATE_LISTEN)
            listeners.insert({row.dwLocalAddr, row.dwLocalPort});
    }

    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto &row = table->table[i];

        if (row.dwState == MIB_TCP_STATE_LISTEN)
            continue;

        if (listeners.contains({row.dwLocalAddr, row.dwLocalPort}))
            continue;

        ByteScanRecord rec;
        rec.pid = row.dwOwningPid;
        rec.remoteAddr = addrToString(row.dwRemoteAddr);
        rec.remotePort = ntohs(static_cast<u_short>(row.dwRemotePort));

        TCP_ESTATS_DATA_ROD_v0 dataRod;
        ULONG rodSize = sizeof(dataRod);
        ULONG rc = GetPerTcpConnectionEStats(
            reinterpret_cast<PMIB_TCPROW>(const_cast<MIB_TCPROW_OWNER_PID *>(&row)),
            TcpConnectionEstatsData,
            NULL, 0, 0,
            NULL, 0, 0,
            reinterpret_cast<PUCHAR>(&dataRod), 0, rodSize);

        if (rc == NO_ERROR) {
            rec.bytesOut = dataRod.DataBytesOut;
            rec.bytesIn  = dataRod.DataBytesIn;
        }

        records.append(rec);
    }
}

QVector<ByteScanRecord> BehavioralAnalyzer::takeSnapshotWithBytes()
{
    QVector<ByteScanRecord> records;
    appendTcpByteRecords(records);
    return records;
}

QVector<NewConnectionInfo> BehavioralAnalyzer::compareBytes(
    const QVector<ByteScanRecord> &before,
    const QVector<ByteScanRecord> &after)
{
    using Key = QPair<quint32, QPair<QString, int>>;

    auto makeKey = [](const ByteScanRecord &r) -> Key {
        return {r.pid, {r.remoteAddr, r.remotePort}};
    };

    QMap<Key, quint64> beforeBytes;
    QMap<quint32, quint64> beforeTotal;
    for (const auto &r : before) {
        beforeBytes[makeKey(r)] = r.bytesOut;
        beforeTotal[r.pid] += r.bytesOut;
    }

    QMap<Key, quint64> afterBytes;
    QMap<quint32, quint64> afterTotal;
    for (const auto &r : after) {
        afterBytes[makeKey(r)] = r.bytesOut;
        afterTotal[r.pid] += r.bytesOut;
    }

    QSet<quint32> flaggedPids;
    for (auto it = afterTotal.begin(); it != afterTotal.end(); ++it) {
        quint64 before = beforeTotal.value(it.key(), 0);
        quint64 delta = it.value() - before;
        if (delta > 2048)
            flaggedPids.insert(it.key());
    }

    QMap<quint32, NewConnectionInfo> pidMap;

    for (const auto &r : after) {
        Key k = makeKey(r);
        bool isNew = !beforeBytes.contains(k);

        if (isNew || flaggedPids.contains(r.pid)) {
            NewConnectionInfo &info = pidMap[r.pid];
            info.pid = r.pid;
            info.newEndpoints.append({r.remoteAddr, r.remotePort});
        }
    }

    for (auto it = pidMap.begin(); it != pidMap.end(); ++it) {
        NewConnectionInfo &info = it.value();
        QString path = processPathFromPid(info.pid);
        if (!path.isEmpty()) {
            int idx = path.lastIndexOf('\\');
            info.processName = (idx >= 0) ? path.mid(idx + 1) : path;
            info.processPath = path;
        }
    }

    QVector<NewConnectionInfo> result;
    for (auto it = pidMap.begin(); it != pidMap.end(); ++it)
        result.append(it.value());

    return result;
}

QSet<quint32> BehavioralAnalyzer::activePidsBetween(
    const QVector<ByteScanRecord> &prev,
    const QVector<ByteScanRecord> &curr)
{
    using Key = QPair<quint32, QPair<QString, int>>;

    QMap<Key, quint64> prevBytes;
    for (const auto &r : prev)
        prevBytes[{r.pid, {r.remoteAddr, r.remotePort}}] = r.bytesOut;

    QMap<quint32, quint64> pidDelta;
    for (const auto &r : curr) {
        Key k{r.pid, {r.remoteAddr, r.remotePort}};
        quint64 before = prevBytes.value(k, 0);
        if (r.bytesOut > before)
            pidDelta[r.pid] += (r.bytesOut - before);
    }

    QSet<quint32> active;
    for (auto it = pidDelta.begin(); it != pidDelta.end(); ++it) {
        if (it.value() > 0)
            active.insert(it.key());
    }
    return active;
}
