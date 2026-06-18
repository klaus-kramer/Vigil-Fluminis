// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#include "FirewallManager.h"

#if FIREWALL_PLATFORM_WINDOWS
#include "platform/windows/ComFirewall.h"
#endif

FirewallManager::FirewallManager() = default;
FirewallManager::~FirewallManager() { shutdown(); }

bool FirewallManager::initialize()
{
#if FIREWALL_PLATFORM_WINDOWS
    m_firewall = std::make_unique<ComFirewall>();
#else
    return false;
#endif

    if (m_firewall && m_firewall->initialize()) {
        m_initialized = true;
        return true;
    }
    return false;
}

void FirewallManager::shutdown()
{
    if (m_firewall) {
        m_firewall->shutdown();
        m_firewall.reset();
    }
    m_initialized = false;
}

bool FirewallManager::isInitialized() const { return m_initialized; }
IFirewall *FirewallManager::firewall() { return m_firewall.get(); }
const IFirewall *FirewallManager::firewall() const { return m_firewall.get(); }
QString FirewallManager::lastError() const
{
    return m_firewall ? m_firewall->lastError() : QStringLiteral("No firewall backend");
}
