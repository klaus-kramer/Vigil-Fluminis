// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#pragma once

#include "FirewallRule.h"
#include <QString>
#include <QVector>
#include <optional>

class IFirewall
{
public:
    virtual ~IFirewall() = default;

    virtual bool initialize() = 0;
    virtual void shutdown() = 0;

    virtual QVector<FirewallRule> rules() const = 0;
    virtual std::optional<FirewallRule> rule(const QString &id) const = 0;

    virtual bool addRule(const FirewallRule &rule) = 0;
    virtual bool removeRule(const QString &id) = 0;
    virtual bool setRuleEnabled(const QString &id, bool enabled) = 0;

    virtual bool firewallEnabled() const = 0;
    virtual bool setFirewallEnabled(bool enabled) = 0;

    virtual bool firewallServiceRunning() const = 0;

    virtual QString lastError() const = 0;
};
