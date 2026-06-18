// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#include "OptionsDialog.h"
#include "core/AiAssistant.h"

#include <QCheckBox>
#include <QSpinBox>
#include <QDoubleSpinBox>
#include <QLabel>
#include <QLineEdit>
#include <QTextEdit>
#include <QPushButton>
#include <QFormLayout>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTabWidget>
#include <QFrame>
#include <QFileDialog>
#include <QSettings>
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>

OptionsDialog::OptionsDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(QStringLiteral("Options"));
    setMinimumWidth(480);
    setMinimumHeight(320);
    setupUi();
    loadSettings();
}

void OptionsDialog::setupUi()
{
    auto root = new QVBoxLayout(this);

    auto tabs = new QTabWidget;

    auto generalTab = new QWidget;
    setupGeneralTab(generalTab);
    tabs->addTab(generalTab, QStringLiteral("General"));

    auto aiTab = new QWidget;
    setupAiTab(aiTab);
    tabs->addTab(aiTab, QStringLiteral("AI Settings"));

    root->addWidget(tabs);

    auto btnLayout = new QHBoxLayout;
    btnLayout->addStretch();
    auto okBtn = new QPushButton(QStringLiteral("OK"));
    okBtn->setDefault(true);
    auto cancelBtn = new QPushButton(QStringLiteral("Cancel"));
    btnLayout->addWidget(cancelBtn);
    btnLayout->addWidget(okBtn);
    root->addLayout(btnLayout);

    connect(okBtn, &QPushButton::clicked, this, [this]() {
        saveSettings();
        accept();
    });
    connect(cancelBtn, &QPushButton::clicked, this, &QDialog::reject);
}

void OptionsDialog::setupGeneralTab(QWidget *tab)
{
    auto form = new QFormLayout(tab);
    form->setSpacing(12);
    form->setContentsMargins(16, 16, 16, 16);

    m_startupCheck = new QCheckBox(QStringLiteral("Launch Vigil Fluminis at Windows startup"));
    form->addRow(m_startupCheck);

    m_autoRefreshCheck = new QCheckBox(QStringLiteral("Auto-refresh firewall rules"));
    form->addRow(m_autoRefreshCheck);

    m_intervalSpin = new QSpinBox;
    m_intervalSpin->setRange(5, 3600);
    m_intervalSpin->setSuffix(QStringLiteral(" seconds"));
    m_intervalSpin->setSingleStep(5);
    form->addRow(QStringLiteral("Refresh interval:"), m_intervalSpin);

    auto separator = new QFrame;
    separator->setFrameShape(QFrame::HLine);
    separator->setFrameShadow(QFrame::Sunken);
    form->addRow(separator);

    m_warnPortsCheck = new QCheckBox(
        QStringLiteral("Warn before allowing known dangerous ports"));
    m_warnPortsCheck->setChecked(true);
    form->addRow(m_warnPortsCheck);

    form->addRow(new QLabel);
}

void OptionsDialog::setupAiTab(QWidget *tab)
{
    auto form = new QFormLayout(tab);
    form->setSpacing(12);
    form->setContentsMargins(16, 16, 16, 16);

    m_aiEnabledCheck = new QCheckBox(QStringLiteral("Enable AI assistant"));
    form->addRow(m_aiEnabledCheck);

    auto modelRow = new QHBoxLayout;
    m_modelPathEdit = new QLineEdit;
    m_modelPathEdit->setPlaceholderText(
        QStringLiteral("Path to .gguf model file (e.g., Qwen2.5-7B-Instruct-Q4_K_M.gguf)"));
    modelRow->addWidget(m_modelPathEdit, 1);

    auto browseBtn = new QPushButton(QStringLiteral("Browse..."));
    browseBtn->setCursor(Qt::PointingHandCursor);
    connect(browseBtn, &QPushButton::clicked, this, &OptionsDialog::onBrowseModel);
    modelRow->addWidget(browseBtn);
    form->addRow(QStringLiteral("Model file:"), modelRow);

    m_modelStatusLabel = new QLabel;
    m_modelStatusLabel->setStyleSheet(QStringLiteral("color: #888; font-style: italic;"));
    form->addRow(QString(), m_modelStatusLabel);

    auto infoLabel = new QLabel(
        QStringLiteral("Download a GGUF model from Huggingface and place it in the resources/models/ subdirectory."));
    infoLabel->setWordWrap(true);
    form->addRow(infoLabel);

    auto separator = new QFrame;
    separator->setFrameShape(QFrame::HLine);
    separator->setFrameShadow(QFrame::Sunken);
    form->addRow(separator);

    m_maxTokensSpin = new QSpinBox;
    m_maxTokensSpin->setRange(64, 4096);
    m_maxTokensSpin->setValue(1024);
    m_maxTokensSpin->setSingleStep(64);
    form->addRow(QStringLiteral("Max tokens:"), m_maxTokensSpin);

    m_temperatureSpin = new QDoubleSpinBox;
    m_temperatureSpin->setRange(0.0, 2.0);
    m_temperatureSpin->setValue(0.3);
    m_temperatureSpin->setSingleStep(0.1);
    m_temperatureSpin->setDecimals(1);
    form->addRow(QStringLiteral("Temperature:"), m_temperatureSpin);

    auto sep2 = new QFrame;
    sep2->setFrameShape(QFrame::HLine);
    sep2->setFrameShadow(QFrame::Sunken);
    form->addRow(sep2);

    auto promptLabel = new QLabel(QStringLiteral("System prompt (sent before each batch):"));
    form->addRow(promptLabel);
    m_systemPromptEdit = new QTextEdit;
    m_systemPromptEdit->setPlaceholderText(QStringLiteral(
        "You are a Windows Firewall security expert..."));
    m_systemPromptEdit->setMinimumHeight(140);
    QFont mono(QStringLiteral("Consolas"));
    mono.setStyleHint(QFont::Monospace);
    mono.setPointSize(10);
    m_systemPromptEdit->setFont(mono);
    form->addRow(m_systemPromptEdit);

    form->addRow(new QLabel);
}

void OptionsDialog::onBrowseModel()
{
    QString path = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("Select GGUF Model File"),
        m_modelPathEdit->text().isEmpty()
            ? QCoreApplication::applicationDirPath() + QStringLiteral("/resources/models")
            : QFileInfo(m_modelPathEdit->text()).absolutePath(),
        QStringLiteral("GGUF Models (*.gguf);;All Files (*)")
    );
    if (!path.isEmpty())
        m_modelPathEdit->setText(QDir::toNativeSeparators(path));
}

void OptionsDialog::loadSettings()
{
    QSettings s(QStringLiteral("Vigil Fluminis"), QStringLiteral("Vigil Fluminis"));

    m_startupCheck->setChecked(
        s.value(QStringLiteral("startup/enabled"), false).toBool());
    m_autoRefreshCheck->setChecked(
        s.value(QStringLiteral("autorefresh/enabled"), false).toBool());
    m_intervalSpin->setValue(
        s.value(QStringLiteral("autorefresh/interval"), 30).toInt());
    m_warnPortsCheck->setChecked(
        s.value(QStringLiteral("warnports/enabled"), true).toBool());

    m_aiEnabledCheck->setChecked(
        s.value(QStringLiteral("ai/enabled"), false).toBool());
    m_modelPathEdit->setText(
        s.value(QStringLiteral("ai/modelPath")).toString());
    m_maxTokensSpin->setValue(
        s.value(QStringLiteral("ai/maxTokens"), 1024).toInt());
    m_temperatureSpin->setValue(
        s.value(QStringLiteral("ai/temperature"), 0.3).toDouble());
    {
        QString saved = s.value(QStringLiteral("ai/systemPrompt")).toString();
        if (saved.isEmpty()) {
            saved = QStringLiteral(
                "You are a Windows Firewall security expert. "
                "Below is a list of firewall rules. "
                "Identify only rules that pose a REAL security threat (e.g. open RDP, "
                "SMB, or known malware ports, remote access tools, unsigned "
                "binaries from temp folders). Ignore harmless rules. "
                "Microsoft and Windows system rules have already been filtered out. "
                "For each real threat, write exactly one line:\n"
                "DELETE RuleName: reason\n"
                "Do NOT list harmless rules. At the end print a summary line: "
                "\"Summary: X/Y rules flagged.\"");
        }
        m_systemPromptEdit->setPlainText(saved);
    }

    QString modelPath = m_modelPathEdit->text();
    bool modelExists = !modelPath.isEmpty() && QFile::exists(modelPath);
    if (modelExists) {
        QFileInfo fi(modelPath);
        qint64 sz = fi.size();
        QString sizeStr;
        if (sz > 1073741824)
            sizeStr = QStringLiteral("%1 GB").arg(sz / 1.0e9, 0, 'f', 1);
        else
            sizeStr = QStringLiteral("%1 MB").arg(sz / 1000000);
        m_modelStatusLabel->setText(QStringLiteral("Model found (%1)").arg(sizeStr));
        m_modelStatusLabel->setStyleSheet(QStringLiteral("color: #2e7d32;"));
    } else if (!modelPath.isEmpty()) {
        m_modelStatusLabel->setText(QStringLiteral("Model file not found"));
        m_modelStatusLabel->setStyleSheet(QStringLiteral("color: #c62828;"));
    } else {
        m_modelStatusLabel->setText(QStringLiteral("No model selected"));
        m_modelStatusLabel->setStyleSheet(QStringLiteral("color: #888; font-style: italic;"));
    }
}

void OptionsDialog::saveSettings()
{
    QSettings s(QStringLiteral("Vigil Fluminis"), QStringLiteral("Vigil Fluminis"));

    s.setValue(QStringLiteral("startup/enabled"), m_startupCheck->isChecked());
    s.setValue(QStringLiteral("autorefresh/enabled"), m_autoRefreshCheck->isChecked());
    s.setValue(QStringLiteral("autorefresh/interval"), m_intervalSpin->value());
    s.setValue(QStringLiteral("warnports/enabled"), m_warnPortsCheck->isChecked());

    s.setValue(QStringLiteral("ai/enabled"), m_aiEnabledCheck->isChecked());
    s.setValue(QStringLiteral("ai/modelPath"), m_modelPathEdit->text());
    s.setValue(QStringLiteral("ai/maxTokens"), m_maxTokensSpin->value());
    s.setValue(QStringLiteral("ai/temperature"), m_temperatureSpin->value());
    s.setValue(QStringLiteral("ai/systemPrompt"), m_systemPromptEdit->toPlainText());

    QSettings reg(QStringLiteral("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
                  QSettings::NativeFormat);
    if (m_startupCheck->isChecked()) {
        QString path = QDir::toNativeSeparators(QCoreApplication::applicationFilePath());
        reg.setValue(QStringLiteral("Vigil Fluminis"), path);
    } else {
        reg.remove(QStringLiteral("Vigil Fluminis"));
    }
}

bool OptionsDialog::autoRefreshEnabled() const
{
    return m_autoRefreshCheck->isChecked();
}

int OptionsDialog::autoRefreshInterval() const
{
    return m_intervalSpin->value();
}

bool OptionsDialog::startWithWindows() const
{
    return m_startupCheck->isChecked();
}

void OptionsDialog::setAutoRefreshEnabled(bool enabled)
{
    m_autoRefreshCheck->setChecked(enabled);
}

void OptionsDialog::setAutoRefreshInterval(int seconds)
{
    m_intervalSpin->setValue(seconds);
}

void OptionsDialog::setStartWithWindows(bool enabled)
{
    m_startupCheck->setChecked(enabled);
}

bool OptionsDialog::warnDangerousPorts() const
{
    return m_warnPortsCheck->isChecked();
}

void OptionsDialog::setWarnDangerousPorts(bool enabled)
{
    m_warnPortsCheck->setChecked(enabled);
}
