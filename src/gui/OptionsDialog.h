// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#pragma once

#include <QDialog>

class QCheckBox;
class QSpinBox;
class QDoubleSpinBox;
class QLineEdit;
class QTextEdit;
class QPushButton;
class QLabel;

class OptionsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit OptionsDialog(QWidget *parent = nullptr);

    bool autoRefreshEnabled() const;
    int autoRefreshInterval() const;
    bool startWithWindows() const;
    bool warnDangerousPorts() const;

    void setAutoRefreshEnabled(bool enabled);
    void setAutoRefreshInterval(int seconds);
    void setStartWithWindows(bool enabled);
    void setWarnDangerousPorts(bool enabled);

private:
    void setupUi();
    void setupGeneralTab(QWidget *tab);
    void setupAiTab(QWidget *tab);
    void loadSettings();
    void saveSettings();
    void onBrowseModel();

    QCheckBox *m_startupCheck = nullptr;
    QCheckBox *m_autoRefreshCheck = nullptr;
    QSpinBox *m_intervalSpin = nullptr;
    QCheckBox *m_warnPortsCheck = nullptr;

    QCheckBox *m_aiEnabledCheck = nullptr;
    QLineEdit *m_modelPathEdit = nullptr;
    QSpinBox *m_maxTokensSpin = nullptr;
    QDoubleSpinBox *m_temperatureSpin = nullptr;
    QLabel *m_modelStatusLabel = nullptr;
    QTextEdit *m_systemPromptEdit = nullptr;
};
