// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#include "TrojanTestDialog.h"
#include "core/IpReputationDb.h"

#include <QVBoxLayout>
#include <QPushButton>
#include <QTableWidget>
#include <QHeaderView>
#include <QLabel>
#include <QFont>
#include <QColor>
#include <QTimer>

TrojanTestDialog *TrojanTestDialog::s_instance = nullptr;

TrojanTestDialog::TrojanTestDialog(QWidget *parent)
    : QDialog(parent)
{
    s_instance = this;
    setupUi();
}

TrojanTestDialog::~TrojanTestDialog()
{
    if (m_keyboardHook)
        UnhookWindowsHookEx(m_keyboardHook);
    s_instance = nullptr;
}

LRESULT CALLBACK TrojanTestDialog::keyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode == HC_ACTION && wParam == WM_KEYDOWN) {
        if (s_instance)
            s_instance->m_keypressSinceLastTick = true;
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

void TrojanTestDialog::setupUi()
{
    setWindowTitle(QStringLiteral("Trojan Test"));
    resize(720, 520);

    auto root = new QVBoxLayout(this);
    root->setSpacing(8);

    auto title = new QLabel(QStringLiteral("Trojan Test - Keypress Correlated Scan"));
    QFont titleFont = title->font();
    titleFont.setPointSize(14);
    titleFont.setBold(true);
    title->setFont(titleFont);
    root->addWidget(title);

    m_instructionLabel = new QLabel(
        QStringLiteral(
            "Please type some keys on the keyboard.\n"
            "The program monitors TCP byte counters in real time.\n"
            "After you click \"Stop typing\", any process that transmitted data\n"
            "immediately after a keypress will be shown below.\n\n"
            "Running with administrator privileges for byte-level detection."));
    m_instructionLabel->setWordWrap(true);
    root->addWidget(m_instructionLabel);

    m_startStopBtn = new QPushButton(QStringLiteral("Start typing"));
    m_startStopBtn->setFixedHeight(40);
    m_startStopBtn->setCursor(Qt::PointingHandCursor);
    QFont btnFont = m_startStopBtn->font();
    btnFont.setPointSize(12);
    btnFont.setBold(true);
    m_startStopBtn->setFont(btnFont);
    connect(m_startStopBtn, &QPushButton::clicked, this, &TrojanTestDialog::onStartStop);
    root->addWidget(m_startStopBtn);

    m_statusLabel = new QLabel(QStringLiteral("Status: Waiting for start"));
    QFont statusFont = m_statusLabel->font();
    statusFont.setPointSize(10);
    statusFont.setItalic(true);
    m_statusLabel->setFont(statusFont);
    root->addWidget(m_statusLabel);

    auto resultLabel = new QLabel(QStringLiteral("Results:"));
    QFont resFont = resultLabel->font();
    resFont.setPointSize(11);
    resFont.setBold(true);
    resultLabel->setFont(resFont);
    root->addWidget(resultLabel);

    m_table = new QTableWidget;
    m_table->setColumnCount(4);
    m_table->setHorizontalHeaderLabels({
        QStringLiteral("Process"),
        QStringLiteral("PID"),
        QStringLiteral("Remote Address"),
        QStringLiteral("Port"),
    });
    m_table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    for (int c = 1; c < m_table->columnCount(); ++c)
        m_table->horizontalHeader()->setSectionResizeMode(c, QHeaderView::ResizeToContents);
    m_table->verticalHeader()->hide();
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    root->addWidget(m_table, 1);

    auto closeBtn = new QPushButton(QStringLiteral("Close"));
    closeBtn->setCursor(Qt::PointingHandCursor);
    closeBtn->setFixedHeight(32);
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);
    root->addWidget(closeBtn);

    m_pollTimer = new QTimer(this);
    m_pollTimer->setInterval(100);
    connect(m_pollTimer, &QTimer::timeout, this, &TrojanTestDialog::onPollTick);
}

void TrojanTestDialog::onStartStop()
{
    if (!m_running) {
        m_table->setRowCount(0);
        m_accumulated.clear();
        m_keypressSinceLastTick = false;
        m_prevSnapshot = BehavioralAnalyzer::takeSnapshotWithBytes();

        m_keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, keyboardHookProc,
            GetModuleHandle(NULL), 0);

        m_pollTimer->start();
        m_running = true;
        m_startStopBtn->setText(QStringLiteral("Stop typing"));
        m_statusLabel->setText(QStringLiteral("Status: Monitoring keystrokes..."));
        m_statusLabel->setStyleSheet(QStringLiteral("color: #c62828;"));
    } else {
        m_pollTimer->stop();
        if (m_keyboardHook) {
            UnhookWindowsHookEx(m_keyboardHook);
            m_keyboardHook = nullptr;
        }
        m_running = false;
        m_startStopBtn->setText(QStringLiteral("Start typing"));

        if (m_accumulated.isEmpty()) {
            m_statusLabel->setText(QStringLiteral("Status: No processes correlated with keystrokes"));
            m_statusLabel->setStyleSheet(QStringLiteral("color: #2e7d32;"));
        } else {
            m_statusLabel->setText(
                QStringLiteral("Status: %1 suspicious process(es) detected")
                    .arg(m_accumulated.size()));
            m_statusLabel->setStyleSheet(QStringLiteral("color: #c62828;"));
        }

        showResults();
    }
}

void TrojanTestDialog::onPollTick()
{
    auto current = BehavioralAnalyzer::takeSnapshotWithBytes();

    if (m_keypressSinceLastTick) {
        m_keypressSinceLastTick = false;

        QSet<quint32> active = BehavioralAnalyzer::activePidsBetween(m_prevSnapshot, current);
        for (quint32 pid : active) {
            QString path;
            {
                HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                if (h) {
                    wchar_t buf[MAX_PATH];
                    DWORD size = MAX_PATH;
                    if (QueryFullProcessImageNameW(h, 0, buf, &size))
                        path = QString::fromWCharArray(buf, size);
                    CloseHandle(h);
                }
            }

            if (!m_accumulated.contains(pid)) {
                NewConnectionInfo info;
                info.pid = pid;
                if (!path.isEmpty()) {
                    int idx = path.lastIndexOf('\\');
                    info.processName = (idx >= 0) ? path.mid(idx + 1) : path;
                    info.processPath = path;
                }
                m_accumulated[pid] = info;
            }
        }
    }

    m_prevSnapshot = current;
}

void TrojanTestDialog::showResults()
{
    if (m_accumulated.isEmpty())
        return;

    for (const auto &info : m_accumulated) {
        int row = m_table->rowCount();
        m_table->setRowCount(row + 1);

        auto nameItem = new QTableWidgetItem(
            info.processName.isEmpty()
                ? QStringLiteral("(PID %1)").arg(info.pid)
                : info.processName);
        if (!info.processPath.isEmpty())
            nameItem->setToolTip(info.processPath);
        QFont f = nameItem->font();
        if (!info.processPath.isEmpty())
            f.setBold(true);
        nameItem->setFont(f);
        m_table->setItem(row, 0, nameItem);

        m_table->setItem(row, 1, new QTableWidgetItem(QString::number(info.pid)));
        m_table->setItem(row, 2, new QTableWidgetItem(QStringLiteral("(multiple)")));
        m_table->setItem(row, 3, new QTableWidgetItem(QStringLiteral("*")));
    }
}
