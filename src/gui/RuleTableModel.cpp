// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#include "RuleTableModel.h"
#include <QColor>
#include <QFont>

RuleTableModel::RuleTableModel(QObject *parent)
    : QAbstractTableModel(parent)
{
}

int RuleTableModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : m_rules.size();
}

int RuleTableModel::columnCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant RuleTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= m_rules.size())
        return {};

    const auto &rule = m_rules.at(index.row());
    const auto &risk = m_riskCache.at(index.row());

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
        case ColName:           return rule.name;
        case ColDirection:      return rule.direction == FirewallRule::Direction::Inbound
                                    ? QStringLiteral("Inbound") : QStringLiteral("Outbound");
        case ColAction:         return rule.action == FirewallRule::Action::Allow
                                    ? QStringLiteral("Allow") : QStringLiteral("Block");
        case ColProtocol: {
            switch (rule.protocol) {
            case FirewallRule::Protocol::TCP: return QStringLiteral("TCP");
            case FirewallRule::Protocol::UDP: return QStringLiteral("UDP");
            default:                          return QStringLiteral("Any");
            }
        }
        case ColApplication:    return rule.applicationPath;
        case ColLocalPorts: {
            QStringList ports;
            for (int p : rule.localPorts)
                ports.append(QString::number(p));
            return ports.join(',');
        }
        case ColRemotePorts: {
            QStringList ports;
            for (int p : rule.remotePorts)
                ports.append(QString::number(p));
            return ports.join(',');
        }
        case ColRemoteAddresses: return rule.remoteAddresses.join(',');
        case ColIpRep:           return risk.ipRepText;
        case ColEnabled:         return rule.enabled
                                    ? QStringLiteral("Yes") : QStringLiteral("No");
        case ColRisk:            return risk.levelText();
        }
    }

    if (role == Qt::CheckStateRole && index.column() == ColEnabled)
        return rule.enabled ? Qt::Checked : Qt::Unchecked;

    if (role == Qt::FontRole && index.column() == ColIpRep && risk.ipRepText == QStringLiteral("Suspicious")) {
        QFont f;
        f.setBold(true);
        return f;
    }

    if (role == Qt::ForegroundRole && index.column() == ColIpRep) {
        if (risk.ipRepText == QStringLiteral("Suspicious"))
            return QColor(Qt::red);
        if (risk.ipRepText == QStringLiteral("Safe"))
            return QColor(0x2E, 0x7D, 0x32);
        return QColor(0x99, 0x99, 0x99);
    }

    if (role == Qt::BackgroundRole) {
        if (risk.level == RiskResult::Safe)
            return {};
        return risk.backgroundColor();
    }

    if (role == Qt::ToolTipRole) {
        if (index.column() == ColIpRep && !risk.ipRepTooltip.isEmpty())
            return risk.ipRepTooltip;
        if (risk.isRisky())
            return risk.details.join(QStringLiteral("\n\n"));
    }

    return {};
}

QVariant RuleTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role != Qt::DisplayRole || orientation != Qt::Horizontal)
        return {};

    switch (section) {
    case ColName:           return QStringLiteral("Name");
    case ColDirection:      return QStringLiteral("Direction");
    case ColAction:         return QStringLiteral("Action");
    case ColProtocol:       return QStringLiteral("Protocol");
    case ColApplication:    return QStringLiteral("Application");
    case ColLocalPorts:     return QStringLiteral("Local Ports");
    case ColRemotePorts:    return QStringLiteral("Remote Ports");
    case ColRemoteAddresses: return QStringLiteral("Remote Addresses");
    case ColIpRep:          return QStringLiteral("IP Rep");
    case ColEnabled:        return QStringLiteral("Enabled");
    case ColRisk:           return QStringLiteral("Risk");
    }
    return {};
}

void RuleTableModel::recomputeRiskCache()
{
    m_riskCache.resize(m_rules.size());
    for (int i = 0; i < m_rules.size(); ++i)
        m_riskCache[i] = RiskAnalyzer::analyze(m_rules[i]);
}

void RuleTableModel::setRules(const QVector<FirewallRule> &rules)
{
    beginResetModel();
    m_rules = rules;
    recomputeRiskCache();
    endResetModel();
}

void RuleTableModel::addRule(const FirewallRule &rule)
{
    beginInsertRows({}, m_rules.size(), m_rules.size());
    m_rules.append(rule);
    m_riskCache.append(RiskAnalyzer::analyze(rule));
    endInsertRows();
}

void RuleTableModel::updateRule(int row, const FirewallRule &rule)
{
    if (row < 0 || row >= m_rules.size())
        return;
    m_rules[row] = rule;
    m_riskCache[row] = RiskAnalyzer::analyze(rule);
    emit dataChanged(index(row, 0), index(row, ColumnCount - 1));
}

void RuleTableModel::removeRule(int row)
{
    if (row < 0 || row >= m_rules.size())
        return;
    beginRemoveRows({}, row, row);
    m_rules.removeAt(row);
    m_riskCache.removeAt(row);
    endRemoveRows();
}

FirewallRule RuleTableModel::ruleAt(int row) const
{
    if (row >= 0 && row < m_rules.size())
        return m_rules.at(row);
    return {};
}

int RuleTableModel::ruleCount() const
{
    return m_rules.size();
}
