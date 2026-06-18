// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#include "AiResultDialog.h"
#include "core/AiAssistant.h"

#include <QTextBrowser>
#include <QPushButton>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QClipboard>
#include <QApplication>
#include <QMetaObject>
#include <QDebug>
#include <thread>

AiResultDialog::AiResultDialog(const FirewallRule &rule, const RiskResult &risk,
                               QWidget *parent)
    : QDialog(parent), m_rule(rule), m_risk(risk)
{
    setWindowTitle(QStringLiteral("AI Assistant — Rule Analysis"));
    setMinimumSize(600, 400);
    setAttribute(Qt::WA_DeleteOnClose);
    setupUi();
}

void AiResultDialog::setupUi()
{
    qWarning() << "AiResultDialog::setupUi: start";
    auto root = new QVBoxLayout(this);
    root->setSpacing(8);
    root->setContentsMargins(12, 12, 12, 12);

    QString titleText = QStringLiteral("Analyzing rule: %1").arg(m_rule.name);
    qWarning() << "AiResultDialog::setupUi: title=" << titleText;
    auto title = new QLabel(titleText);
    QFont tf = title->font();
    tf.setPointSize(12);
    tf.setBold(true);
    title->setFont(tf);
    root->addWidget(title);

    m_statusLabel = new QLabel(QStringLiteral("Thinking..."));
    m_statusLabel->setStyleSheet(QStringLiteral("color: #888; font-style: italic;"));
    root->addWidget(m_statusLabel);

    m_textBrowser = new QTextBrowser;
    m_textBrowser->setOpenExternalLinks(false);
    m_textBrowser->setReadOnly(true);
    {
        QFont f = m_textBrowser->font();
        f.setPointSize(11);
        m_textBrowser->setFont(f);
    }
    root->addWidget(m_textBrowser, 1);

    auto btnLayout = new QHBoxLayout;
    m_copyBtn = new QPushButton(QStringLiteral("Copy"));
    m_copyBtn->setEnabled(false);
    m_copyBtn->setCursor(Qt::PointingHandCursor);
    connect(m_copyBtn, &QPushButton::clicked, this, &AiResultDialog::onCopy);

    m_againBtn = new QPushButton(QStringLiteral("Ask again"));
    m_againBtn->setEnabled(false);
    m_againBtn->setCursor(Qt::PointingHandCursor);
    connect(m_againBtn, &QPushButton::clicked, this, &AiResultDialog::onAskAgain);

    auto closeBtn = new QPushButton(QStringLiteral("Close"));
    closeBtn->setCursor(Qt::PointingHandCursor);
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::close);

    btnLayout->addWidget(m_copyBtn);
    btnLayout->addWidget(m_againBtn);
    btnLayout->addStretch();
    btnLayout->addWidget(closeBtn);
    root->addLayout(btnLayout);

    qWarning() << "AiResultDialog::setupUi: calling runInference";
    runInference();
    qWarning() << "AiResultDialog::setupUi: done";
}

void AiResultDialog::runInference()
{
    qWarning() << "AiResultDialog::runInference: start";
    QWidget *self = this;

    FirewallRule rule = m_rule;
    RiskResult risk = m_risk;
    std::thread t([rule, risk, self]() {
        AiResult res = AiAssistant::analyzeRule(rule, risk);
        if (res.success) {
            QMetaObject::invokeMethod(self, [self, res]() {
                static_cast<AiResultDialog *>(self)->onResultReady(res.answer, res.inferenceMs);
            }, Qt::QueuedConnection);
        } else {
            QMetaObject::invokeMethod(self, [self, res]() {
                static_cast<AiResultDialog *>(self)->onError(res.error);
            }, Qt::QueuedConnection);
        }
    });
    t.detach();
}

void AiResultDialog::onResultReady(const QString &answer, qint64 ms)
{
    m_statusLabel->setText(QStringLiteral("Done (%1 ms)").arg(ms));
    m_textBrowser->setPlainText(answer);
    m_copyBtn->setEnabled(true);
    m_againBtn->setEnabled(true);
}

void AiResultDialog::onError(const QString &error)
{
    m_statusLabel->setText(QStringLiteral("Error"));
    m_textBrowser->setPlainText(QStringLiteral("AI analysis failed:\n%1").arg(error));
    m_copyBtn->setEnabled(false);
    m_againBtn->setEnabled(true);
}

void AiResultDialog::onCopy()
{
    QApplication::clipboard()->setText(m_textBrowser->toPlainText());
    m_copyBtn->setText(QStringLiteral("Copied!"));
}

void AiResultDialog::onAskAgain()
{
    m_textBrowser->clear();
    m_statusLabel->setText(QStringLiteral("Thinking..."));
    m_copyBtn->setEnabled(false);
    m_againBtn->setEnabled(false);
    runInference();
}
