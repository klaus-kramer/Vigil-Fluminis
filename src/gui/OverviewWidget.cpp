// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#include "OverviewWidget.h"
#include "core/IFirewall.h"
#include "core/FirewallRule.h"
#include "core/ThreatDatabase.h"
#include "core/RiskAnalyzer.h"
#include "OptionsDialog.h"
#include "TrojanTestDialog.h"
#include "platform/windows/Elevation.h"

#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QFont>
#include <QTimer>
#include <QMessageBox>
#include <QPixmap>
#include <QCoreApplication>
#include <QDir>
#include <QDebug>
#include <QSet>

OverviewWidget::OverviewWidget(IFirewall *firewall, QWidget *parent)
    : QWidget(parent), m_firewall(firewall)
{
    setupUi();
}

void OverviewWidget::setupUi()
{
    auto root = new QVBoxLayout(this);
    root->setContentsMargins(40, 12, 40, 4);
    root->setSpacing(8);

    auto title = new QLabel(QStringLiteral("Vigil Fluminis - Guardian of the river"));
    QFont titleFont = title->font();
    titleFont.setPointSize(22);
    titleFont.setBold(true);
    title->setFont(titleFont);
    root->addWidget(title);

    auto cards = new QHBoxLayout;
    cards->setSpacing(24);

    auto statusBox = new QGroupBox(QStringLiteral("Firewall Status"));
    auto statusLayout = new QVBoxLayout(statusBox);
    statusLayout->setSpacing(12);

    m_statusLabel = new QLabel;
    QFont statusFont = m_statusLabel->font();
    statusFont.setPointSize(16);
    statusFont.setBold(true);
    m_statusLabel->setFont(statusFont);
    statusLayout->addWidget(m_statusLabel);

    m_firewallToggle = new QPushButton;
    m_firewallToggle->setFixedHeight(36);
    m_firewallToggle->setCursor(Qt::PointingHandCursor);
    statusLayout->addWidget(m_firewallToggle);

    connect(m_firewallToggle, &QPushButton::clicked, this, [this]() {
        if (!m_firewall) return;
        Elevation::requestElevation({QStringLiteral("--toggle-firewall")});
        QTimer::singleShot(1000, this, &OverviewWidget::refresh);
    });

    statusLayout->addSpacing(8);

    m_serviceStatusLabel = new QLabel;
    QFont serviceFont = m_serviceStatusLabel->font();
    serviceFont.setPointSize(12);
    serviceFont.setBold(true);
    m_serviceStatusLabel->setFont(serviceFont);
    statusLayout->addWidget(m_serviceStatusLabel);

    m_serviceToggle = new QPushButton;
    m_serviceToggle->setFixedHeight(32);
    m_serviceToggle->setCursor(Qt::PointingHandCursor);
    connect(m_serviceToggle, &QPushButton::clicked, this, [this]() {
        if (!m_firewall) return;
        bool running = m_firewall->firewallServiceRunning();
        Elevation::requestElevation({
            QStringLiteral("--service"),
            running ? QStringLiteral("stop") : QStringLiteral("start")
        });
        QTimer::singleShot(1000, this, &OverviewWidget::refresh);
    });
    statusLayout->addWidget(m_serviceToggle);

    statusBox->setMinimumWidth(260);
    statusBox->setMaximumWidth(300);
    cards->addWidget(statusBox);

    auto statsBox = new QGroupBox(QStringLiteral("Rule Statistics"));
    auto statsLayout = new QGridLayout(statsBox);
    statsLayout->setSpacing(4);
    statsLayout->setHorizontalSpacing(8);
    for (int c = 0; c < 4; ++c)
        statsLayout->setColumnStretch(c, 0);

    auto addValue = [&](const QString &label, QLabel *&valueLabel, int row, int col) {
        auto lbl = new QLabel(label);
        QFont f = lbl->font();
        f.setPointSize(10);
        lbl->setFont(f);
        statsLayout->addWidget(lbl, row, col * 2, Qt::AlignLeft);

        valueLabel = new QLabel(QStringLiteral("--"));
        QFont vf = valueLabel->font();
        vf.setPointSize(16);
        vf.setBold(true);
        valueLabel->setFont(vf);
        statsLayout->addWidget(valueLabel, row, col * 2 + 1);
    };

    m_totalRulesLabel = new QLabel(QStringLiteral("--"));
    QFont totalFont = m_totalRulesLabel->font();
    totalFont.setPointSize(16);
    totalFont.setBold(true);
    m_totalRulesLabel->setFont(totalFont);
    statsLayout->addWidget(new QLabel(QStringLiteral("Total Rules:")), 0, 0, Qt::AlignLeft);
    statsLayout->addWidget(m_totalRulesLabel, 0, 1, 1, 3);

    addValue(QStringLiteral("Allow:"),    m_allowedLabel,    1, 0);
    addValue(QStringLiteral("Block:"),    m_blockedLabel,    1, 1);
    addValue(QStringLiteral("Enabled:"),  m_enabledLabel,    2, 0);
    addValue(QStringLiteral("Disabled:"), m_disabledLabel,   2, 1);

    m_riskyRulesLabel = new QLabel(QStringLiteral("--"));
    QFont riskyFont = m_riskyRulesLabel->font();
    riskyFont.setPointSize(16);
    riskyFont.setBold(true);
    m_riskyRulesLabel->setFont(riskyFont);
    statsLayout->addWidget(new QLabel(QStringLiteral("Risky Rules:")), 3, 0, Qt::AlignLeft);
    statsLayout->addWidget(m_riskyRulesLabel, 3, 1, 1, 3);

    m_suspiciousTitleLabel = new QLabel(QStringLiteral("Top 3 suspicious apps:"));
    QFont suspTitleFont = m_suspiciousTitleLabel->font();
    suspTitleFont.setPointSize(10);
    suspTitleFont.setBold(true);
    suspTitleFont.setUnderline(true);
    m_suspiciousTitleLabel->setFont(suspTitleFont);
    statsLayout->addWidget(m_suspiciousTitleLabel, 4, 0, 1, 4);

    for (int i = 0; i < 3; ++i) {
        m_suspiciousNames[i] = new QLabel(QStringLiteral("---"));
        QFont nf = m_suspiciousNames[i]->font();
        nf.setPointSize(16);
        nf.setBold(true);
        m_suspiciousNames[i]->setFont(nf);
        statsLayout->addWidget(m_suspiciousNames[i], 5 + i, 0, 1, 3);

        m_suspiciousScores[i] = new QLabel(QStringLiteral("--"));
        QFont sf = m_suspiciousScores[i]->font();
        sf.setPointSize(16);
        sf.setBold(true);
        m_suspiciousScores[i]->setFont(sf);
        statsLayout->addWidget(m_suspiciousScores[i], 5 + i, 3);
    }

    statsBox->setMinimumWidth(440);
    cards->addWidget(statsBox);

    root->addLayout(cards);

    auto midSection = new QHBoxLayout;

    auto leftPanel = new QVBoxLayout;
    leftPanel->setSpacing(8);

    auto makeBtn = [&](const QString &text) {
        auto btn = new QPushButton(text);
        btn->setFixedHeight(36);
        btn->setCursor(Qt::PointingHandCursor);
        QFont f = btn->font();
        f.setPointSize(11);
        btn->setFont(f);
        return btn;
    };

    auto analyseRow = new QHBoxLayout;
    analyseRow->setSpacing(8);

    auto manageBtn = makeBtn(QStringLiteral("Analyse Rules"));
    connect(manageBtn, &QPushButton::clicked, this, &OverviewWidget::manageRulesClicked);
    manageBtn->setMinimumWidth(160);
    analyseRow->addWidget(manageBtn);

    auto appsBtn = makeBtn(QStringLiteral("Analyse Apps"));
    connect(appsBtn, &QPushButton::clicked, this, &OverviewWidget::manageAppsClicked);
    appsBtn->setMinimumWidth(160);
    analyseRow->addWidget(appsBtn);

    auto connBtn = makeBtn(QStringLiteral("Analyse Connections"));
    connect(connBtn, &QPushButton::clicked, this, &OverviewWidget::manageConnectionsClicked);
    connBtn->setMinimumWidth(160);
    analyseRow->addWidget(connBtn);

    leftPanel->addLayout(analyseRow);

    auto aiRow = new QHBoxLayout;
    aiRow->setSpacing(8);

    auto aiSettingsBtn = makeBtn(QStringLiteral("AI Settings"));
    aiSettingsBtn->setMinimumWidth(120);
    connect(aiSettingsBtn, &QPushButton::clicked, this, &OverviewWidget::aiSettingsClicked);
    aiRow->addWidget(aiSettingsBtn);

    aiRow->addStretch();
    leftPanel->addLayout(aiRow);

    auto trojanBtn = makeBtn(QStringLiteral("Trojan test with admin"));
    connect(trojanBtn, &QPushButton::clicked, this, [this]() {
        if (Elevation::isElevated()) {
            TrojanTestDialog dlg(this->parentWidget());
            dlg.exec();
        } else {
            Elevation::requestElevation({QStringLiteral("--trojan-test-gui")});
        }
    });
    leftPanel->addWidget(trojanBtn);

    auto optionsBtn = makeBtn(QStringLiteral("Options"));
    connect(optionsBtn, &QPushButton::clicked, this, [this]() {
        OptionsDialog dlg(this);
        if (dlg.exec() == QDialog::Accepted)
            emit optionsChanged();
    });
    leftPanel->addWidget(optionsBtn);

    auto helpBtn = makeBtn(QStringLiteral("Help"));
    connect(helpBtn, &QPushButton::clicked, this, [this]() {
        QMessageBox::information(this, QStringLiteral("Help"),
            QStringLiteral(
                "Vigil Fluminis - Guardian of the river v0.4.0\n"
                "Analyse and Manage Firewall rules with a simple graphical interface.\n\n"
                "---\n"
                "Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License.\n"
                "See LICENSE.txt for details."));
    });
    leftPanel->addWidget(helpBtn);

    leftPanel->addStretch();
    midSection->addLayout(leftPanel);
    midSection->addStretch();

    auto imageLabel = new QLabel;
    QString imgPath = QCoreApplication::applicationDirPath()
        + QStringLiteral("/Vigil_Fluminis_256.png");
    QPixmap pix(imgPath);
    if (!pix.isNull())
        imageLabel->setPixmap(pix);
    imageLabel->setFixedSize(256, 256);
    midSection->addWidget(imageLabel);

    root->addLayout(midSection);

    auto licenseLabel = new QLabel(QStringLiteral(
        "Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License.\n"
        "See LICENSE.txt for details."));
    QFont licFont = licenseLabel->font();
    licFont.setPointSize(9);
    licenseLabel->setFont(licFont);
    licenseLabel->setStyleSheet(QStringLiteral("color: #888;"));
    root->addWidget(licenseLabel);

    refresh();
}

void OverviewWidget::refresh()
{
    if (!m_firewall)
        return;

    bool fwOn = m_firewall->firewallEnabled();

    m_statusLabel->setText(fwOn
        ? QStringLiteral("ON")
        : QStringLiteral("OFF"));
    m_statusLabel->setStyleSheet(fwOn
        ? QStringLiteral("color: #2e7d32;")
        : QStringLiteral("color: #c62828;"));

    m_firewallToggle->setText(fwOn
        ? QStringLiteral("Turn Off Firewall")
        : QStringLiteral("Turn On Firewall"));

    bool svcRunning = m_firewall->firewallServiceRunning();
    m_serviceStatusLabel->setText(svcRunning
        ? QStringLiteral("Service: Running")
        : QStringLiteral("Service: Stopped"));
    m_serviceStatusLabel->setStyleSheet(svcRunning
        ? QStringLiteral("color: #2e7d32;")
        : QStringLiteral("color: #c62828;"));
    m_serviceToggle->setText(svcRunning
        ? QStringLiteral("Stop Service")
        : QStringLiteral("Start Service"));

    auto rules = m_firewall->rules();

    int total = rules.size();
    int allow = 0, block = 0;
    int enabled = 0, disabled = 0;

    for (const auto &r : rules) {
        if (r.action == FirewallRule::Action::Allow) ++allow;
        else ++block;
        if (r.enabled) ++enabled;
        else ++disabled;
    }

    m_totalRulesLabel->setText(QString::number(total));
    m_allowedLabel->setText(QString::number(allow));
    m_blockedLabel->setText(QString::number(block));
    m_enabledLabel->setText(QString::number(enabled));
    m_disabledLabel->setText(QString::number(disabled));

    QSet<QString> uniqueApps;
    int risky = 0;
    for (const auto &r : rules) {
        if (!r.applicationPath.isEmpty())
            uniqueApps.insert(r.applicationPath);
        if (RiskAnalyzer::analyze(r).isRisky())
            ++risky;
    }
    m_riskyRulesLabel->setText(QString::number(risky));
    m_riskyRulesLabel->setStyleSheet(risky > 0
        ? QStringLiteral("color: #e65100;")
        : QStringLiteral("color: #2e7d32;"));
}

void OverviewWidget::setTopSuspiciousApps(const QStringList &names, const QList<int> &scores)
{
    for (int i = 0; i < 3; ++i) {
        if (i < names.size() && !names[i].isEmpty()) {
            m_suspiciousNames[i]->setText(names[i]);
            int score = i < scores.size() ? scores[i] : -1;
            m_suspiciousScores[i]->setText(score >= 0 ? QString::number(score) : QStringLiteral("--"));
            m_suspiciousScores[i]->setStyleSheet(score > 0
                ? QStringLiteral("color: #c62828;")
                : QStringLiteral("color: #2e7d32;"));
        } else {
            m_suspiciousNames[i]->setText(QStringLiteral("---"));
            m_suspiciousScores[i]->setText(QStringLiteral("--"));
            m_suspiciousScores[i]->setStyleSheet(QString());
        }
    }
}
