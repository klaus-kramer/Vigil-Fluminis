// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#pragma once

#include "FirewallRule.h"
#include "RiskAnalyzer.h"
#include <QString>
#include <QStringList>
#include <functional>

struct AiConfig
{
    QString modelPath;
    int maxTokens = 1024;
    float temperature = 0.3f;
    bool enabled = false;
    QString systemPrompt;
};

struct AiResult
{
    QString answer;
    qint64 inferenceMs = 0;
    bool success = false;
    QString error;
};

class AiAssistant
{
public:
    enum ChatFormat { ChatML, Phi3 };

    static void setConfig(const AiConfig &cfg);
    static AiConfig config();

    static bool isModelLoaded();
    static QString loadModel();
    static void unloadModel();

    static AiResult analyzeRule(const FirewallRule &rule, const RiskResult &risk);

    static QString buildPrompt(const FirewallRule &rule, const RiskResult &risk);
    static ChatFormat chatFormat();

    static QString lastError();

private:
    static AiResult runInference(const QString &prompt, int maxTokens);

    static AiConfig s_config;
    static QString s_lastError;

    static void *s_model;
    static void *s_ctx;
    static ChatFormat s_chatFormat;
};
