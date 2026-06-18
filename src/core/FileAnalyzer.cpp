// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#include "FileAnalyzer.h"

#include <QFileInfo>
#include <QByteArray>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#pragma comment(lib, "version.lib")

struct KnownPublisher { const wchar_t *name; };
static const KnownPublisher s_knownPublishers[] = {
    { L"Microsoft Corporation" },
    { L"Microsoft Windows" },
    { L"Google LLC" },
    { L"Google Inc." },
    { L"Apple Inc." },
    { L"Adobe Inc." },
    { L"Adobe Systems Incorporated" },
    { L"Mozilla Corporation" },
    { L"Oracle America, Inc." },
    { L"Intel Corporation" },
    { L"NVIDIA Corporation" },
    { L"Advanced Micro Devices, Inc." },
    { L"AMD" },
    { L"Spotify AB" },
    { L"Valve Corporation" },
    { L"GitHub, Inc." },
    { L"The Qt Company" },
    { L"JetBrains s.r.o." },
    { L"Red Hat, Inc." },
    { L"Docker Inc." },
    { L"Slack Technologies, LLC" },
    { L"Discord Inc." },
    { L"Meta Platforms, Inc." },
    { L"Amazon.com, Inc." },
    { L"Amazon Web Services, Inc." },
    { L"Zoom Video Communications, Inc." },
    { L"VideoLAN" },
    { L"7-zip" },
    { L"Notepad++" },
    { L"Oracle Corporation" },
    { L"VMware, Inc." },
    { L"Canonical Group Limited" },
    { L"The Apache Software Foundation" },
    { L"Eclipse Foundation" },
    { L"Free Software Foundation, Inc." },
    { L"GIMP" },
    { L"Inkscape" },
    { L"Audacity Team" },
    { L"OpenSSL Corporation" },
};

bool FileAnalyzer::isKnownPublisher(const QString &publisher)
{
    if (publisher.isEmpty())
        return false;

    for (const auto &kp : s_knownPublishers) {
        if (publisher == QString::fromWCharArray(kp.name))
            return true;
    }
    return false;
}

FileInfoResult FileAnalyzer::analyze(const QString &filePath)
{
    FileInfoResult result;

    QFileInfo fi(filePath);
    if (filePath.isEmpty() || !fi.exists())
        return result;

    result.lastModified = fi.lastModified();

    std::wstring widePath = filePath.toStdWString();

    DWORD dummy = 0;
    DWORD size = GetFileVersionInfoSizeW(widePath.c_str(), &dummy);
    if (size == 0)
        return result;

    QByteArray buffer(static_cast<int>(size), '\0');
    if (!GetFileVersionInfoW(widePath.c_str(), 0, size, buffer.data()))
        return result;

    result.hasVersionInfo = true;

    DWORD *trans = nullptr;
    UINT transLen = 0;
    VerQueryValueW(buffer.data(), L"\\VarFileInfo\\Translation",
                   reinterpret_cast<void **>(&trans), &transLen);

    if (trans && transLen >= 4) {
        WORD lang = LOWORD(trans[0]);
        WORD cp   = HIWORD(trans[0]);

        wchar_t sub[64];
        swprintf(sub, ARRAYSIZE(sub),
                 L"\\StringFileInfo\\%04x%04x\\CompanyName", lang, cp);

        wchar_t *val = nullptr;
        UINT valLen = 0;
        if (VerQueryValueW(buffer.data(), sub,
                           reinterpret_cast<void **>(&val), &valLen) && val && valLen > 1)
            result.companyName = QString::fromWCharArray(val, valLen - 1);

        swprintf(sub, ARRAYSIZE(sub),
                 L"\\StringFileInfo\\%04x%04x\\OriginalFilename", lang, cp);

        val = nullptr;
        valLen = 0;
        if (VerQueryValueW(buffer.data(), sub,
                           reinterpret_cast<void **>(&val), &valLen) && val && valLen > 1)
            result.originalFilename = QString::fromWCharArray(val, valLen - 1);
    }

    return result;
}
