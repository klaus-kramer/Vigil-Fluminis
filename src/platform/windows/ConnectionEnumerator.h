// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#pragma once

#include "core/ConnectionInfo.h"
#include <QVector>

class ConnectionEnumerator
{
public:
    static QVector<ConnectionInfo> enumerateConnections();
};
