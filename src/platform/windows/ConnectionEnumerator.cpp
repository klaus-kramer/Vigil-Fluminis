// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#include "ConnectionEnumerator.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <psapi.h>
#include <QDebug>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

static QString addrToString(DWORD addr)
{
    IN_ADDR ia;
    ia.S_un.S_addr = addr;
    wchar_t buf[INET_ADDRSTRLEN];
    InetNtopW(AF_INET, &ia, buf, INET_ADDRSTRLEN);
    return QString::fromWCharArray(buf);
}

static QString tcpStateToString(DWORD state)
{
    switch (state) {
    case MIB_TCP_STATE_CLOSED:     return QStringLiteral("CLOSED");
    case MIB_TCP_STATE_LISTEN:     return QStringLiteral("LISTEN");
    case MIB_TCP_STATE_SYN_SENT:   return QStringLiteral("SYN_SENT");
    case MIB_TCP_STATE_SYN_RCVD:   return QStringLiteral("SYN_RCVD");
    case MIB_TCP_STATE_ESTAB:      return QStringLiteral("ESTABLISHED");
    case MIB_TCP_STATE_FIN_WAIT1:  return QStringLiteral("FIN_WAIT1");
    case MIB_TCP_STATE_FIN_WAIT2:  return QStringLiteral("FIN_WAIT2");
    case MIB_TCP_STATE_CLOSE_WAIT: return QStringLiteral("CLOSE_WAIT");
    case MIB_TCP_STATE_CLOSING:    return QStringLiteral("CLOSING");
    case MIB_TCP_STATE_LAST_ACK:   return QStringLiteral("LAST_ACK");
    case MIB_TCP_STATE_TIME_WAIT:  return QStringLiteral("TIME_WAIT");
    default:                       return QStringLiteral("UNKNOWN");
    }
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

static void enumerateTcp(QVector<ConnectionInfo> &result)
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
        Q_UNUSED(row);

        ConnectionInfo ci;
        ci.protocol = 6;
        ci.protocolStr = QStringLiteral("TCP");
        ci.localAddr = addrToString(row.dwLocalAddr);
        ci.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
        ci.remoteAddr = addrToString(row.dwRemoteAddr);
        ci.remotePort = ntohs(static_cast<u_short>(row.dwRemotePort));
        ci.state = tcpStateToString(row.dwState);
        ci.pid = row.dwOwningPid;
        ci.processPath = processPathFromPid(row.dwOwningPid);
        if (!ci.processPath.isEmpty()) {
            int idx = ci.processPath.lastIndexOf('\\');
            ci.processName = (idx >= 0) ? ci.processPath.mid(idx + 1) : ci.processPath;
        }
        result.append(ci);
    }
}

static void enumerateUdp(QVector<ConnectionInfo> &result)
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

        ConnectionInfo ci;
        ci.protocol = 17;
        ci.protocolStr = QStringLiteral("UDP");
        ci.localAddr = addrToString(row.dwLocalAddr);
        ci.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
        ci.remoteAddr = QStringLiteral("*");
        ci.remotePort = 0;
        ci.state = QStringLiteral("LISTENING");
        ci.pid = row.dwOwningPid;
        ci.processPath = processPathFromPid(row.dwOwningPid);
        if (!ci.processPath.isEmpty()) {
            int idx = ci.processPath.lastIndexOf('\\');
            ci.processName = (idx >= 0) ? ci.processPath.mid(idx + 1) : ci.processPath;
        }
        result.append(ci);
    }
}

QVector<ConnectionInfo> ConnectionEnumerator::enumerateConnections()
{
    QVector<ConnectionInfo> result;
    enumerateTcp(result);
    enumerateUdp(result);
    return result;
}
