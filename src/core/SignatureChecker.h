// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#pragma once

#include <QString>

struct SignatureResult
{
    enum Status {
        NotChecked,
        Verified,
        Unsigned,
        SelfSigned,
        Expired,
        Revoked,
        UntrustedRoot,
        Error
    };

    Status status = NotChecked;
    QString publisher;
    QString details;

    bool isTrusted() const { return status == Verified; }
    QString statusText() const;
    QString statusTooltip() const;
};

class SignatureChecker
{
public:
    static SignatureResult check(const QString &filePath);
};
