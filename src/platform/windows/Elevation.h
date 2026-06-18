// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#pragma once

#include <QStringList>

namespace Elevation {

bool requestElevation(const QStringList &args);
bool isElevated();

}
