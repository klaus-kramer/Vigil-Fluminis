// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#include "AiAssistant.h"
#include "ThreatDatabase.h"
#include "IpReputationDb.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QDebug>

#include "llama.h"

#include <thread>
#include <chrono>
#include <vector>
#include <random>

AiConfig AiAssistant::s_config;
QString AiAssistant::s_lastError;
void *AiAssistant::s_model = nullptr;
void *AiAssistant::s_ctx = nullptr;
AiAssistant::ChatFormat AiAssistant::s_chatFormat = ChatML;

void AiAssistant::setConfig(const AiConfig &cfg)
{
    bool reload = (cfg.modelPath != s_config.modelPath)
               || (cfg.enabled != s_config.enabled);
    s_config = cfg;
    if (reload) {
        unloadModel();
        if (s_config.enabled && !s_config.modelPath.isEmpty())
            loadModel();
    }
}

AiConfig AiAssistant::config()
{
    return s_config;
}

bool AiAssistant::isModelLoaded()
{
    return s_model != nullptr && s_ctx != nullptr;
}

QString AiAssistant::loadModel()
{
    unloadModel();

    if (s_config.modelPath.isEmpty()) {
        s_lastError = QStringLiteral("No model path configured");
        return s_lastError;
    }

    if (!QFile::exists(s_config.modelPath)) {
        s_lastError = QStringLiteral("Model file not found: %1").arg(s_config.modelPath);
        qWarning() << s_lastError;
        return s_lastError;
    }

    llama_backend_init();

    llama_model_params model_params = llama_model_default_params();
    model_params.n_gpu_layers = 0;

    llama_model *model = llama_load_model_from_file(
        s_config.modelPath.toUtf8().constData(), model_params);
    if (!model) {
        s_lastError = QStringLiteral("Failed to load model");
        return s_lastError;
    }

    llama_context_params ctx_params = llama_context_default_params();
    ctx_params.n_ctx = 2048;
    ctx_params.n_threads = static_cast<int>(std::thread::hardware_concurrency());
    ctx_params.n_batch = 512;

    llama_context *ctx = llama_new_context_with_model(model, ctx_params);
    if (!ctx) {
        llama_free_model(model);
        s_lastError = QStringLiteral("Failed to create context");
        return s_lastError;
    }

    s_model = model;
    s_ctx = ctx;

    s_chatFormat = ChatML;
    {
        char desc[128] = {};
        if (llama_model_desc(model, desc, sizeof(desc)) > 0) {
            QString modelName = QString::fromUtf8(desc).toLower();
            if (modelName.contains(QStringLiteral("phi")))
                s_chatFormat = Phi3;
        }
    }

    s_lastError.clear();
    return {};
}

void AiAssistant::unloadModel()
{
    if (s_ctx) {
        llama_free(static_cast<llama_context *>(s_ctx));
        s_ctx = nullptr;
    }
    if (s_model) {
        llama_free_model(static_cast<llama_model *>(s_model));
        s_model = nullptr;
    }
    llama_backend_free();
}

QString AiAssistant::buildPrompt(const FirewallRule &rule, const RiskResult &risk)
{
    QStringList lines;

    if (s_chatFormat == Phi3) {
        lines << QStringLiteral("<|system|>");
    } else {
        lines << QStringLiteral("<|im_start|>system");
    }
    if (!s_config.systemPrompt.isEmpty()) {
        lines << s_config.systemPrompt;
    } else {
        lines << QStringLiteral(
            "You are a Windows Firewall security expert. "
            "Analyze the given firewall rule and provide a thorough, detailed assessment. "
            "Write several paragraphs covering:\n"
            "- What the rule does and its purpose\n"
            "- The security risk it poses (or why it is safe)\n"
            "- Specific concerns: overly permissive settings, missing application path, wide-open ports, etc.\n"
            "- A clear recommendation: keep, restrict, or delete\n"
            "Be comprehensive. Do not summarize in one or two sentences.");
    }
    if (s_chatFormat == Phi3) {
        lines << QStringLiteral("<|end|>");
        lines << QStringLiteral("<|user|>");
    } else {
        lines << QStringLiteral("<|im_end|>");
        lines << QStringLiteral("<|im_start|>user");
    }

    lines << QStringLiteral("Rule: \"%1\"").arg(rule.name);
    if (!rule.description.isEmpty())
        lines << QStringLiteral("Description: %1").arg(rule.description);
    lines << QStringLiteral("Application: %1").arg(
        rule.applicationPath.isEmpty() ? QStringLiteral("(any)") : rule.applicationPath);
    lines << QStringLiteral("Direction: %1").arg(
        rule.direction == FirewallRule::Direction::Inbound ? QStringLiteral("Inbound") : QStringLiteral("Outbound"));
    lines << QStringLiteral("Action: %1").arg(
        rule.action == FirewallRule::Action::Allow ? QStringLiteral("Allow") : QStringLiteral("Block"));
    lines << QStringLiteral("Protocol: %1").arg(
        rule.protocol == FirewallRule::Protocol::TCP ? QStringLiteral("TCP") :
        rule.protocol == FirewallRule::Protocol::UDP ? QStringLiteral("UDP") : QStringLiteral("Any"));

    QStringList localPorts;
    for (int p : rule.localPorts) localPorts << QString::number(p);
    lines << QStringLiteral("Local Ports: %1").arg(
        localPorts.isEmpty() ? QStringLiteral("any") : localPorts.join(QStringLiteral(", ")));

    QStringList remotePorts;
    for (int p : rule.remotePorts) remotePorts << QString::number(p);
    lines << QStringLiteral("Remote Ports: %1").arg(
        remotePorts.isEmpty() ? QStringLiteral("any") : remotePorts.join(QStringLiteral(", ")));

    lines << QStringLiteral("Remote Addresses: %1").arg(
        rule.remoteAddresses.isEmpty() ? QStringLiteral("any") : rule.remoteAddresses.join(QStringLiteral(", ")));

    lines << QStringLiteral("Enabled: %1").arg(rule.enabled ? QStringLiteral("Yes") : QStringLiteral("No"));

    lines << QStringLiteral("");
    lines << QStringLiteral("Risk Score: %1/10 (%2)").arg(risk.score).arg(risk.levelText());
    if (!risk.details.isEmpty()) {
        lines << QStringLiteral("Risk Details:");
        for (const auto &d : risk.details)
            lines << QStringLiteral("- %1").arg(d);
    }
    if (!risk.ipRepText.isEmpty())
        lines << QStringLiteral("IP Reputation: %1").arg(risk.ipRepText);

    if (s_chatFormat == Phi3) {
        lines << QStringLiteral("<|end|>");
        lines << QStringLiteral("<|assistant|>");
    } else {
        lines << QStringLiteral("<|im_end|>");
        lines << QStringLiteral("<|im_start|>assistant");
    }

    return lines.join(QStringLiteral("\n"));
}

AiResult AiAssistant::runInference(const QString &prompt, int maxTokens)
{
    AiResult result;
    llama_context *ctx = static_cast<llama_context *>(s_ctx);
    llama_model *model = static_cast<llama_model *>(s_model);
    const llama_vocab *vocab = llama_model_get_vocab(model);

    llama_memory_clear(llama_get_memory(ctx), true);

    int32_t ctxSize = llama_n_ctx(ctx);
    int32_t maxPromptTokens = ctxSize - maxTokens - 64;
    if (maxPromptTokens < 64)
        maxPromptTokens = 64;

    QByteArray promptUtf8 = prompt.toUtf8();

    std::vector<llama_token> tokens(maxPromptTokens);
    int n_tokens = llama_tokenize(vocab,
        promptUtf8.constData(), static_cast<int32_t>(promptUtf8.size()),
        tokens.data(), static_cast<int32_t>(tokens.size()),
        true, false);

    if (n_tokens < 0) {
        int32_t needed = -n_tokens;
        result.error = QStringLiteral("Prompt too long (%1 tokens, context %2)")
            .arg(needed).arg(ctxSize);
        return result;
    }
    if (n_tokens == 0) {
        result.error = QStringLiteral("Tokenization failed");
        return result;
    }
    tokens.resize(n_tokens);

    auto startTime = std::chrono::steady_clock::now();

    auto *smpl = llama_sampler_chain_init(llama_sampler_chain_default_params());
    llama_sampler_chain_add(smpl, llama_sampler_init_temp(s_config.temperature));
    llama_sampler_chain_add(smpl, llama_sampler_init_top_p(0.9f, 1));
    llama_sampler_chain_add(smpl, llama_sampler_init_dist(
        static_cast<uint32_t>(std::random_device{}())));

    QString output;
    int curTokens = 0;

    while (curTokens < maxTokens) {
        llama_batch batch = llama_batch_get_one(tokens.data(), static_cast<int32_t>(tokens.size()));
        if (llama_decode(ctx, batch) != 0) {
            result.error = QStringLiteral("Decode failed at token %1").arg(curTokens);
            break;
        }

        llama_token token = llama_sampler_sample(smpl, ctx, -1);

        if (llama_vocab_is_eog(vocab, token))
            break;

        char buf[16];
        int n = llama_token_to_piece(vocab, token, buf, sizeof(buf), 0, true);
        if (n > 0)
            output.append(QString::fromUtf8(buf, n));

        if (output.contains(QStringLiteral("<|im_end|>"))
         || output.contains(QStringLiteral("<|im_start|>"))
         || output.contains(QStringLiteral("<|end|>"))
         || output.contains(QStringLiteral("<|user|>"))
         || output.contains(QStringLiteral("<|assistant|>"))) {
            break;
        }

        tokens = { token };
        ++curTokens;
    }

    llama_sampler_free(smpl);

    auto endTime = std::chrono::steady_clock::now();
    result.inferenceMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime).count();

    result.answer = output.trimmed();
    int idx;
    if ((idx = result.answer.indexOf(QStringLiteral("<|im_end|>"))) >= 0
     || (idx = result.answer.indexOf(QStringLiteral("<|im_start|>"))) >= 0
     || (idx = result.answer.indexOf(QStringLiteral("<|end|>"))) >= 0) {
        result.answer.truncate(idx);
    }
    result.answer = result.answer.trimmed();
    result.success = true;
    return result;
}

AiResult AiAssistant::analyzeRule(const FirewallRule &rule, const RiskResult &risk)
{
    if (!isModelLoaded()) {
        AiResult r;
        r.error = QStringLiteral("AI model not loaded");
        return r;
    }

    QString prompt = buildPrompt(rule, risk);
    return runInference(prompt, s_config.maxTokens);
}

QString AiAssistant::lastError()
{
    return s_lastError;
}

AiAssistant::ChatFormat AiAssistant::chatFormat()
{
    return s_chatFormat;
}
