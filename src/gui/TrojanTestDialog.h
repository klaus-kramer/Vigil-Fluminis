// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#pragma once

#include <QDialog>
#include <QVector>
#include <QSet>
#include <QMap>
#include <windows.h>
#include "core/BehavioralAnalyzer.h"

class QPushButton;
class QTableWidget;
class QLabel;
class QTimer;

class TrojanTestDialog : public QDialog
{
    Q_OBJECT

public:
    explicit TrojanTestDialog(QWidget *parent = nullptr);
    ~TrojanTestDialog() override;

private:
    void setupUi();
    void onStartStop();
    void onPollTick();
    void showResults();

    static LRESULT CALLBACK keyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam);

    QPushButton *m_startStopBtn = nullptr;
    QLabel *m_statusLabel = nullptr;
    QTableWidget *m_table = nullptr;
    QLabel *m_instructionLabel = nullptr;

    HHOOK m_keyboardHook = nullptr;
    QTimer *m_pollTimer = nullptr;

    bool m_running = false;
    bool m_keypressSinceLastTick = false;
    QVector<ByteScanRecord> m_prevSnapshot;
    QMap<quint32, NewConnectionInfo> m_accumulated;

    static TrojanTestDialog *s_instance;
};
