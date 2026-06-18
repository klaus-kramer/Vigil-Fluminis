// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#include "Elevation.h"
#include <QCoreApplication>
#include <QDir>
#include <windows.h>
#include <shellapi.h>

namespace Elevation {

bool requestElevation(const QStringList &args)
{
    QStringList allArgs;
    allArgs << QStringLiteral("--elevate") << args;

    QString argStr;
    for (const auto &a : allArgs)
        argStr += QStringLiteral("\"%1\" ").arg(a);

    HINSTANCE result = ShellExecuteW(
        nullptr,
        L"runas",
        QCoreApplication::applicationFilePath().toStdWString().c_str(),
        argStr.trimmed().toStdWString().c_str(),
        QDir::currentPath().toStdWString().c_str(),
        SW_SHOWNORMAL);

    return reinterpret_cast<INT_PTR>(result) > 32;
}

bool isElevated()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;

    TOKEN_ELEVATION elevation;
    DWORD size = sizeof(TOKEN_ELEVATION);
    BOOL success = GetTokenInformation(
        token, TokenElevation, &elevation, size, &size);

    CloseHandle(token);
    return success && elevation.TokenIsElevated;
}

}
