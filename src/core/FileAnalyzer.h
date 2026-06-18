// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#pragma once

#include <QString>
#include <QDateTime>
#include <QSet>

struct FileInfoResult
{
    QString companyName;
    QString originalFilename;
    QDateTime lastModified;
    bool hasVersionInfo = false;
};

class FileAnalyzer
{
public:
    static FileInfoResult analyze(const QString &filePath);
    static bool isKnownPublisher(const QString &publisher);
};
