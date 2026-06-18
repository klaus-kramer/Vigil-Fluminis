// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#include "RuleDialog.h"

#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QFormLayout>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QFileDialog>
#include <QDialogButtonBox>

RuleDialog::RuleDialog(QWidget *parent)
    : QDialog(parent)
{
    setupUi();
}

RuleDialog::RuleDialog(const FirewallRule &rule, QWidget *parent)
    : QDialog(parent)
{
    setupUi();
    populate(rule);
}

void RuleDialog::setupUi()
{
    setWindowTitle(QStringLiteral("Firewall Rule"));
    setMinimumWidth(450);

    auto mainLayout = new QVBoxLayout(this);

    auto form = new QFormLayout;

    m_nameEdit = new QLineEdit;
    m_nameEdit->setPlaceholderText(QStringLiteral("Rule name"));
    form->addRow(QStringLiteral("Name:"), m_nameEdit);

    m_descEdit = new QLineEdit;
    m_descEdit->setPlaceholderText(QStringLiteral("Optional description"));
    form->addRow(QStringLiteral("Description:"), m_descEdit);

    auto appLayout = new QHBoxLayout;
    m_appPathEdit = new QLineEdit;
    m_appPathEdit->setPlaceholderText(QStringLiteral("Path to application (optional)"));
    auto browseBtn = new QPushButton(QStringLiteral("Browse..."));
    connect(browseBtn, &QPushButton::clicked, this, &RuleDialog::onBrowseApp);
    appLayout->addWidget(m_appPathEdit);
    appLayout->addWidget(browseBtn);
    form->addRow(QStringLiteral("Application:"), appLayout);

    m_directionCombo = new QComboBox;
    m_directionCombo->addItem(QStringLiteral("Inbound"), static_cast<int>(FirewallRule::Direction::Inbound));
    m_directionCombo->addItem(QStringLiteral("Outbound"), static_cast<int>(FirewallRule::Direction::Outbound));
    form->addRow(QStringLiteral("Direction:"), m_directionCombo);

    m_actionCombo = new QComboBox;
    m_actionCombo->addItem(QStringLiteral("Allow"), static_cast<int>(FirewallRule::Action::Allow));
    m_actionCombo->addItem(QStringLiteral("Block"), static_cast<int>(FirewallRule::Action::Block));
    form->addRow(QStringLiteral("Action:"), m_actionCombo);

    m_protocolCombo = new QComboBox;
    m_protocolCombo->addItem(QStringLiteral("Any"), static_cast<int>(FirewallRule::Protocol::Any));
    m_protocolCombo->addItem(QStringLiteral("TCP"), static_cast<int>(FirewallRule::Protocol::TCP));
    m_protocolCombo->addItem(QStringLiteral("UDP"), static_cast<int>(FirewallRule::Protocol::UDP));
    form->addRow(QStringLiteral("Protocol:"), m_protocolCombo);

    m_localPortsEdit = new QLineEdit;
    m_localPortsEdit->setPlaceholderText(QStringLiteral("e.g. 80,443"));
    form->addRow(QStringLiteral("Local Ports:"), m_localPortsEdit);

    m_remotePortsEdit = new QLineEdit;
    m_remotePortsEdit->setPlaceholderText(QStringLiteral("e.g. 80,443"));
    form->addRow(QStringLiteral("Remote Ports:"), m_remotePortsEdit);

    m_remoteAddrsEdit = new QLineEdit;
    m_remoteAddrsEdit->setPlaceholderText(QStringLiteral("e.g. 10.0.0.0/8,192.168.1.100"));
    form->addRow(QStringLiteral("Remote Addresses:"), m_remoteAddrsEdit);

    m_enabledCheck = new QCheckBox(QStringLiteral("Rule enabled"));
    m_enabledCheck->setChecked(true);
    form->addRow(QString(), m_enabledCheck);

    mainLayout->addLayout(form);

    auto buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    mainLayout->addWidget(buttons);
}

void RuleDialog::populate(const FirewallRule &rule)
{
    m_nameEdit->setText(rule.name);
    m_descEdit->setText(rule.description);
    m_appPathEdit->setText(rule.applicationPath);
    m_directionCombo->setCurrentIndex(
        rule.direction == FirewallRule::Direction::Inbound ? 0 : 1);
    m_actionCombo->setCurrentIndex(
        rule.action == FirewallRule::Action::Allow ? 0 : 1);
    m_protocolCombo->setCurrentIndex(static_cast<int>(rule.protocol));

    QStringList lports;
    for (int p : rule.localPorts)
        lports.append(QString::number(p));
    m_localPortsEdit->setText(lports.join(','));

    QStringList rports;
    for (int p : rule.remotePorts)
        rports.append(QString::number(p));
    m_remotePortsEdit->setText(rports.join(','));

    m_remoteAddrsEdit->setText(rule.remoteAddresses.join(','));

    m_enabledCheck->setChecked(rule.enabled);
}

FirewallRule RuleDialog::rule() const
{
    FirewallRule r;
    r.name = m_nameEdit->text().trimmed();
    r.description = m_descEdit->text().trimmed();
    r.applicationPath = m_appPathEdit->text().trimmed();
    r.direction = static_cast<FirewallRule::Direction>(
        m_directionCombo->currentData().toInt());
    r.action = static_cast<FirewallRule::Action>(
        m_actionCombo->currentData().toInt());
    r.protocol = static_cast<FirewallRule::Protocol>(
        m_protocolCombo->currentData().toInt());

    for (const auto &p : m_localPortsEdit->text().split(',')) {
        bool ok = false;
        int v = p.trimmed().toInt(&ok);
        if (ok) r.localPorts.append(v);
    }

    for (const auto &p : m_remotePortsEdit->text().split(',')) {
        bool ok = false;
        int v = p.trimmed().toInt(&ok);
        if (ok) r.remotePorts.append(v);
    }

    for (const auto &a : m_remoteAddrsEdit->text().split(',')) {
        QString t = a.trimmed();
        if (!t.isEmpty())
            r.remoteAddresses.append(t);
    }

    r.enabled = m_enabledCheck->isChecked();
    return r;
}

void RuleDialog::onBrowseApp()
{
    QString path = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("Select Application"),
        QString(),
        QStringLiteral("Executables (*.exe);;All Files (*)"));
    if (!path.isEmpty())
        m_appPathEdit->setText(path);
}
