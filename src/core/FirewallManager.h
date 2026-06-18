// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#pragma once

#include "IFirewall.h"
#include <memory>

class FirewallManager
{
public:
    FirewallManager();
    ~FirewallManager();

    bool initialize();
    void shutdown();
    bool isInitialized() const;

    IFirewall *firewall();
    const IFirewall *firewall() const;

    QString lastError() const;

private:
    std::unique_ptr<IFirewall> m_firewall;
    bool m_initialized = false;
};
