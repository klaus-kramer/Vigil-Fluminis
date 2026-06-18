// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#pragma once

#include <QDialog>
#include "core/FirewallRule.h"

class QLineEdit;
class QComboBox;
class QCheckBox;

class RuleDialog : public QDialog
{
    Q_OBJECT

public:
    explicit RuleDialog(QWidget *parent = nullptr);
    explicit RuleDialog(const FirewallRule &rule, QWidget *parent = nullptr);

    FirewallRule rule() const;

private slots:
    void onBrowseApp();

private:
    void setupUi();
    void populate(const FirewallRule &rule);

    QLineEdit *m_nameEdit = nullptr;
    QLineEdit *m_descEdit = nullptr;
    QLineEdit *m_appPathEdit = nullptr;
    QComboBox *m_directionCombo = nullptr;
    QComboBox *m_actionCombo = nullptr;
    QComboBox *m_protocolCombo = nullptr;
    QLineEdit *m_localPortsEdit = nullptr;
    QLineEdit *m_remotePortsEdit = nullptr;
    QLineEdit *m_remoteAddrsEdit = nullptr;
    QCheckBox *m_enabledCheck = nullptr;
};
