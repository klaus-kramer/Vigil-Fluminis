// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#pragma once

#include "FirewallRule.h"
#include <QVector>
#include <QString>

struct DangerousPort {
    int port;
    QString service;
    QString risk;
    QString recommendation;
};

class ThreatDatabase
{
public:
    static bool isRiskyRule(const FirewallRule &rule);
    static bool isPortDangerous(int port);
    static QVector<QString> riskDescriptions(const FirewallRule &rule);

private:
    static void ensureLoaded();
    static void writeDefaults(const QString &path);

    static QVector<DangerousPort> s_ports;
    static bool s_loaded;
};
