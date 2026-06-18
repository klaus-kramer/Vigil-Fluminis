// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#pragma once

#include "core/IFirewall.h"
#include <windows.h>
#include <netfw.h>

class ComFirewall : public IFirewall
{
public:
    ComFirewall();
    ~ComFirewall() override;

    bool initialize() override;
    void shutdown() override;

    QVector<FirewallRule> rules() const override;
    std::optional<FirewallRule> rule(const QString &id) const override;

    bool addRule(const FirewallRule &rule) override;
    bool removeRule(const QString &id) override;
    bool setRuleEnabled(const QString &id, bool enabled) override;

    bool firewallEnabled() const override;
    bool setFirewallEnabled(bool enabled) override;

    bool firewallServiceRunning() const override;

    QString lastError() const override;

private:
    QString comError(HRESULT hr) const;
    FirewallRule fromComRule(INetFwRule *comRule) const;

    HRESULT m_lastHr = S_OK;
    INetFwPolicy2 *m_policy = nullptr;
};
