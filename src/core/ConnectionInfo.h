// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#pragma once

#include <QString>
#include "KnownMalwareDb.h"
#include "SignatureChecker.h"
#include "FileAnalyzer.h"
#include "IpReputationDb.h"

struct ConnectionInfo
{
    int protocol = 0;
    QString protocolStr;
    QString localAddr;
    int localPort = 0;
    QString remoteAddr;
    int remotePort = 0;
    QString state;

    quint32 pid = 0;
    QString processPath;
    QString processName;

    MalwareResult repResult;
    SignatureResult sigResult;
    FileInfoResult fileInfo;
    QString dirInfo;
    bool suspiciousPort = false;
    IpReputationResult ipRepResult;

    int suspiciousScore = 0;
};
