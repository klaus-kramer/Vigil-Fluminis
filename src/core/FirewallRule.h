// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#pragma once

#include <QString>
#include <QVector>

struct FirewallRule
{
    enum class Direction { Inbound, Outbound };
    enum class Action { Allow, Block };
    enum class Protocol { TCP, UDP, Any };

    enum ProfileFlag {
        ProfileDomain  = 1,
        ProfilePrivate = 2,
        ProfilePublic  = 4,
        ProfileAll     = ProfileDomain | ProfilePrivate | ProfilePublic
    };

    QString id;
    QString name;
    QString description;
    QString applicationPath;

    Direction direction = Direction::Inbound;
    Action action = Action::Allow;
    Protocol protocol = Protocol::Any;

    QVector<int> localPorts;
    QVector<int> remotePorts;
    QVector<QString> remoteAddresses;

    int profiles = ProfileAll;

    bool enabled = true;
};
