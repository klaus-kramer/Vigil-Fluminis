// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#include "ComFirewall.h"
#include <QDebug>
#include <comdef.h>
#include <comutil.h>
#include <icftypes.h>
#include <winsvc.h>



ComFirewall::ComFirewall() = default;

ComFirewall::~ComFirewall()
{
    shutdown();
}

bool ComFirewall::initialize()
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        m_lastHr = hr;
        return false;
    }

    hr = CoCreateInstance(
        __uuidof(NetFwPolicy2),
        nullptr,
        CLSCTX_INPROC_SERVER,
        __uuidof(INetFwPolicy2),
        reinterpret_cast<void **>(&m_policy));

    if (FAILED(hr)) {
        m_lastHr = hr;
        CoUninitialize();
        return false;
    }

    return true;
}

void ComFirewall::shutdown()
{
    if (m_policy) {
        m_policy->Release();
        m_policy = nullptr;
    }
    CoUninitialize();
}

QVector<FirewallRule> ComFirewall::rules() const
{
    QVector<FirewallRule> result;

    if (!m_policy)
        return result;

    INetFwRules *fwRules = nullptr;
    HRESULT hr = m_policy->get_Rules(&fwRules);
    if (FAILED(hr)) {
        const_cast<ComFirewall *>(this)->m_lastHr = hr;
        return result;
    }

    long count = 0;
    fwRules->get_Count(&count);

    IUnknown *enumerator = nullptr;
    hr = fwRules->get__NewEnum(&enumerator);
    if (SUCCEEDED(hr)) {
        IEnumVARIANT *varEnum = nullptr;
        hr = enumerator->QueryInterface(IID_PPV_ARGS(&varEnum));
        if (SUCCEEDED(hr)) {
            VARIANT variant;
            VariantInit(&variant);
            while (varEnum->Next(1, &variant, nullptr) == S_OK) {
                INetFwRule *comRule = nullptr;
                hr = V_UNKNOWN(&variant)->QueryInterface(IID_PPV_ARGS(&comRule));
                if (SUCCEEDED(hr)) {
                    result.append(fromComRule(comRule));
                    comRule->Release();
                }
                VariantClear(&variant);
            }
            varEnum->Release();
        }
        enumerator->Release();
    }

    fwRules->Release();
    return result;
}

std::optional<FirewallRule> ComFirewall::rule(const QString &id) const
{
    if (!m_policy)
        return std::nullopt;

    INetFwRules *fwRules = nullptr;
    HRESULT hr = m_policy->get_Rules(&fwRules);
    if (FAILED(hr)) {
        const_cast<ComFirewall *>(this)->m_lastHr = hr;
        return std::nullopt;
    }

    _bstr_t bstrId(id.toStdWString().c_str());
    INetFwRule *comRule = nullptr;
    hr = fwRules->Item(bstrId, &comRule);
    fwRules->Release();

    if (FAILED(hr) || !comRule)
        return std::nullopt;

    FirewallRule rule = fromComRule(comRule);
    comRule->Release();
    return rule;
}

bool ComFirewall::addRule(const FirewallRule &rule)
{
    if (!m_policy)
        return false;

    INetFwRules *fwRules = nullptr;
    HRESULT hr = m_policy->get_Rules(&fwRules);
    if (FAILED(hr)) {
        m_lastHr = hr;
        return false;
    }

    INetFwRule *comRule = nullptr;
    hr = CoCreateInstance(
        __uuidof(NetFwRule),
        nullptr,
        CLSCTX_INPROC_SERVER,
        __uuidof(INetFwRule),
        reinterpret_cast<void **>(&comRule));

    if (FAILED(hr)) {
        m_lastHr = hr;
        fwRules->Release();
        return false;
    }

    _bstr_t bstrName(rule.name.toStdWString().c_str());
    _bstr_t bstrDesc(rule.description.toStdWString().c_str());
    _bstr_t bstrApp(rule.applicationPath.toStdWString().c_str());

    comRule->put_Name(bstrName);
    comRule->put_Description(bstrDesc);

    if (!rule.applicationPath.isEmpty())
        comRule->put_ApplicationName(bstrApp);

    comRule->put_Direction(
        rule.direction == FirewallRule::Direction::Inbound
            ? NET_FW_RULE_DIR_IN
            : NET_FW_RULE_DIR_OUT);

    comRule->put_Action(
        rule.action == FirewallRule::Action::Allow
            ? NET_FW_ACTION_ALLOW
            : NET_FW_ACTION_BLOCK);

    comRule->put_Enabled(rule.enabled ? VARIANT_TRUE : VARIANT_FALSE);

    switch (rule.protocol) {
    case FirewallRule::Protocol::TCP:
        comRule->put_Protocol(NET_FW_IP_PROTOCOL_TCP);
        break;
    case FirewallRule::Protocol::UDP:
        comRule->put_Protocol(NET_FW_IP_PROTOCOL_UDP);
        break;
    default:
        comRule->put_Protocol(NET_FW_IP_PROTOCOL_ANY);
        break;
    }

    if (!rule.localPorts.isEmpty()) {
        QString portStr;
        for (int p : rule.localPorts) {
            if (!portStr.isEmpty()) portStr += ',';
            portStr += QString::number(p);
        }
        _bstr_t bstrPorts(portStr.toStdWString().c_str());
        comRule->put_LocalPorts(bstrPorts);
    }

    if (!rule.remotePorts.isEmpty()) {
        QString portStr;
        for (int p : rule.remotePorts) {
            if (!portStr.isEmpty()) portStr += ',';
            portStr += QString::number(p);
        }
        _bstr_t bstrPorts(portStr.toStdWString().c_str());
        comRule->put_RemotePorts(bstrPorts);
    }

    if (!rule.remoteAddresses.isEmpty()) {
        QString addrStr;
        for (const auto &a : rule.remoteAddresses) {
            if (!addrStr.isEmpty()) addrStr += ',';
            addrStr += a;
        }
        _bstr_t bstrAddrs(addrStr.toStdWString().c_str());
        comRule->put_RemoteAddresses(bstrAddrs);
    }

    hr = fwRules->Add(comRule);
    if (FAILED(hr))
        m_lastHr = hr;

    comRule->Release();
    fwRules->Release();
    return SUCCEEDED(hr);
}

bool ComFirewall::removeRule(const QString &id)
{
    if (!m_policy)
        return false;

    INetFwRules *fwRules = nullptr;
    HRESULT hr = m_policy->get_Rules(&fwRules);
    if (FAILED(hr)) {
        m_lastHr = hr;
        return false;
    }

    _bstr_t bstrId(id.toStdWString().c_str());
    hr = fwRules->Remove(bstrId);
    if (FAILED(hr))
        m_lastHr = hr;

    fwRules->Release();
    return SUCCEEDED(hr);
}

bool ComFirewall::setRuleEnabled(const QString &id, bool enabled)
{
    if (!m_policy)
        return false;

    INetFwRules *fwRules = nullptr;
    HRESULT hr = m_policy->get_Rules(&fwRules);
    if (FAILED(hr)) {
        m_lastHr = hr;
        return false;
    }

    _bstr_t bstrId(id.toStdWString().c_str());
    INetFwRule *comRule = nullptr;
    hr = fwRules->Item(bstrId, &comRule);
    if (SUCCEEDED(hr) && comRule) {
        comRule->put_Enabled(enabled ? VARIANT_TRUE : VARIANT_FALSE);
        comRule->Release();
    } else {
        m_lastHr = hr;
    }

    fwRules->Release();
    return SUCCEEDED(hr);
}

bool ComFirewall::firewallEnabled() const
{
    if (!m_policy)
        return false;

    long activeProfiles = 0;
    HRESULT hr = m_policy->get_CurrentProfileTypes(&activeProfiles);
    if (FAILED(hr)) {
        const_cast<ComFirewall *>(this)->m_lastHr = hr;
        return false;
    }

    static const NET_FW_PROFILE_TYPE2 profiles[] = {
        NET_FW_PROFILE2_DOMAIN,
        NET_FW_PROFILE2_PRIVATE,
        NET_FW_PROFILE2_PUBLIC,
    };

    for (auto p : profiles) {
        if (activeProfiles & static_cast<long>(p)) {
            VARIANT_BOOL enabled = VARIANT_FALSE;
            m_policy->get_FirewallEnabled(p, &enabled);
            if (enabled != VARIANT_TRUE)
                return false;
        }
    }

    return true;
}

bool ComFirewall::setFirewallEnabled(bool enabled)
{
    if (!m_policy)
        return false;

    long activeProfiles = 0;
    HRESULT hr = m_policy->get_CurrentProfileTypes(&activeProfiles);
    if (FAILED(hr)) {
        m_lastHr = hr;
        return false;
    }

    static const NET_FW_PROFILE_TYPE2 profiles[] = {
        NET_FW_PROFILE2_DOMAIN,
        NET_FW_PROFILE2_PRIVATE,
        NET_FW_PROFILE2_PUBLIC,
    };

    bool allOk = true;
    for (auto p : profiles) {
        if (activeProfiles & static_cast<long>(p)) {
            hr = m_policy->put_FirewallEnabled(
                p, enabled ? VARIANT_TRUE : VARIANT_FALSE);
            if (FAILED(hr)) {
                m_lastHr = hr;
                allOk = false;
            }
        }
    }

    return allOk;
}

bool ComFirewall::firewallServiceRunning() const
{
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
        return false;

    SC_HANDLE service = OpenServiceW(scm, L"mpssvc", SERVICE_QUERY_STATUS);
    if (!service) {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS_PROCESS ssStatus;
    DWORD bytesNeeded = 0;
    bool running = false;

    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                             reinterpret_cast<LPBYTE>(&ssStatus),
                             sizeof(ssStatus), &bytesNeeded)) {
        running = (ssStatus.dwCurrentState == SERVICE_RUNNING);
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return running;
}

QString ComFirewall::lastError() const
{
    return comError(m_lastHr);
}

QString ComFirewall::comError(HRESULT hr) const
{
    _com_error err(hr);
    return QString::fromWCharArray(err.ErrorMessage());
}

FirewallRule ComFirewall::fromComRule(INetFwRule *comRule) const
{
    FirewallRule rule;

    BSTR bstrVal = nullptr;

    if (SUCCEEDED(comRule->get_Name(&bstrVal)) && bstrVal) {
        rule.name = QString::fromWCharArray(bstrVal);
        rule.id = rule.name;
        SysFreeString(bstrVal);
        bstrVal = nullptr;
    }

    if (SUCCEEDED(comRule->get_Description(&bstrVal)) && bstrVal) {
        rule.description = QString::fromWCharArray(bstrVal);
        SysFreeString(bstrVal);
    }

    if (SUCCEEDED(comRule->get_ApplicationName(&bstrVal)) && bstrVal) {
        rule.applicationPath = QString::fromWCharArray(bstrVal);
        SysFreeString(bstrVal);
    }

    NET_FW_RULE_DIRECTION dir;
    if (SUCCEEDED(comRule->get_Direction(&dir))) {
        rule.direction = (dir == NET_FW_RULE_DIR_IN)
                             ? FirewallRule::Direction::Inbound
                             : FirewallRule::Direction::Outbound;
    }

    NET_FW_ACTION fwAction;
    if (SUCCEEDED(comRule->get_Action(&fwAction))) {
        rule.action = (fwAction == NET_FW_ACTION_ALLOW)
                          ? FirewallRule::Action::Allow
                          : FirewallRule::Action::Block;
    }

    long protocol = NET_FW_IP_PROTOCOL_ANY;
    if (SUCCEEDED(comRule->get_Protocol(&protocol))) {
        if (protocol == NET_FW_IP_PROTOCOL_TCP)
            rule.protocol = FirewallRule::Protocol::TCP;
        else if (protocol == NET_FW_IP_PROTOCOL_UDP)
            rule.protocol = FirewallRule::Protocol::UDP;
        else
            rule.protocol = FirewallRule::Protocol::Any;
    }

    if (SUCCEEDED(comRule->get_LocalPorts(&bstrVal)) && bstrVal) {
        QString ports = QString::fromWCharArray(bstrVal);
        for (const auto &p : ports.split(',')) {
            bool ok = false;
            int val = p.trimmed().toInt(&ok);
            if (ok) rule.localPorts.append(val);
        }
        SysFreeString(bstrVal);
    }

    if (SUCCEEDED(comRule->get_RemotePorts(&bstrVal)) && bstrVal) {
        QString ports = QString::fromWCharArray(bstrVal);
        for (const auto &p : ports.split(',')) {
            bool ok = false;
            int val = p.trimmed().toInt(&ok);
            if (ok) rule.remotePorts.append(val);
        }
        SysFreeString(bstrVal);
    }

    if (SUCCEEDED(comRule->get_RemoteAddresses(&bstrVal)) && bstrVal) {
        QString addrs = QString::fromWCharArray(bstrVal);
        for (const auto &a : addrs.split(','))
            rule.remoteAddresses.append(a.trimmed());
        SysFreeString(bstrVal);
    }

    VARIANT_BOOL enabled = VARIANT_FALSE;
    if (SUCCEEDED(comRule->get_Enabled(&enabled)))
        rule.enabled = (enabled == VARIANT_TRUE);

    return rule;
}
