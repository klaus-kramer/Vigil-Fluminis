// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#pragma once

#include <QAbstractTableModel>
#include <QVector>
#include "core/FirewallRule.h"
#include "core/RiskAnalyzer.h"

class RuleTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    enum Column {
        ColName,
        ColDirection,
        ColAction,
        ColProtocol,
        ColApplication,
        ColLocalPorts,
        ColRemotePorts,
        ColRemoteAddresses,
        ColIpRep,
        ColEnabled,
        ColRisk,
        ColumnCount
    };

    explicit RuleTableModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = {}) const override;
    int columnCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    void setRules(const QVector<FirewallRule> &rules);
    void addRule(const FirewallRule &rule);
    void updateRule(int row, const FirewallRule &rule);
    void removeRule(int row);
    FirewallRule ruleAt(int row) const;
    int ruleCount() const;

private:
    void recomputeRiskCache();

    QVector<FirewallRule> m_rules;
    QVector<RiskResult> m_riskCache;
};
