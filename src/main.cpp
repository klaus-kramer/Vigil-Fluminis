// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#include <QApplication>
#include <QIcon>
#include <QMessageBox>
#include <QFile>
#include <QDataStream>

#include <windows.h>

#include "core/FirewallManager.h"
#include "core/BackupManager.h"
#include "gui/MainWindow.h"
#include "gui/TrojanTestDialog.h"

#if FIREWALL_PLATFORM_WINDOWS
#include "platform/windows/Elevation.h"
#endif

static int runElevated(int argc, char *argv[]);
static FirewallRule loadRuleFromFile(const QString &path);

int main(int argc, char *argv[])
{
    {
        QStringList args;
        for (int i = 0; i < argc; ++i)
            args << QString::fromLocal8Bit(argv[i]);
        if (args.contains(QStringLiteral("--elevate")))
            return runElevated(argc, argv);
    }

    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("Vigil Fluminis - Guardian of the river"));
    app.setApplicationVersion(QStringLiteral("0.4.0"));
    app.setWindowIcon(QIcon(QStringLiteral("Vigil Fluminis.ico")));

    auto manager = std::make_unique<FirewallManager>();
    if (!manager->initialize()) {
        QMessageBox::critical(
            nullptr,
            QStringLiteral("Firewall Error"),
            QStringLiteral("Failed to initialize firewall backend:\n%1")
                .arg(manager->lastError()));
        return 1;
    }

    MainWindow window(std::move(manager));
    window.show();
    return app.exec();
}

static int runElevated(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QStringList args = app.arguments();

    args.removeFirst();
    args.removeFirst();

    if (args.isEmpty())
        return 0;

    QString cmd = args.first();
    args.removeFirst();

    if (cmd == QStringLiteral("--trojan-test-gui")) {
        TrojanTestDialog dlg;
        dlg.exec();
        return 0;
    }

    FirewallManager manager;
    if (!manager.initialize()) {
        QMessageBox::critical(
            nullptr,
            QStringLiteral("Firewall Error"),
            QStringLiteral("Operation failed:\n%1").arg(manager.lastError()));
        return 1;
    }

    auto *fw = manager.firewall();
    if (!fw)
        return 1;

    BackupManager::createBackup(fw->rules());

    bool ok = false;

    if (cmd == QStringLiteral("--toggle-firewall")) {
        ok = fw->setFirewallEnabled(!fw->firewallEnabled());
    } else if (cmd == QStringLiteral("--delete-rule") && !args.isEmpty()) {
        ok = fw->removeRule(args.first());
    } else if (cmd == QStringLiteral("--set-enabled") && args.size() >= 2) {
        ok = fw->setRuleEnabled(args.at(0), args.at(1) == QStringLiteral("1"));
    } else if (cmd == QStringLiteral("--service") && !args.isEmpty()) {
        QString action = args.first();
        HINSTANCE h = ShellExecuteW(nullptr, L"runas", L"net",
            action == QStringLiteral("start")
                ? L"start mpssvc"
                : L"stop  mpssvc",
            nullptr, SW_HIDE);
        ok = reinterpret_cast<INT_PTR>(h) > 32;
    } else if (cmd == QStringLiteral("--add-rule") && !args.isEmpty()) {
        FirewallRule rule = loadRuleFromFile(args.first());
        ok = fw->addRule(rule);
        QFile::remove(args.first());
    } else if (cmd == QStringLiteral("--edit-rule") && !args.isEmpty()) {
        FirewallRule rule = loadRuleFromFile(args.first());
        QFile::remove(args.first());
        if (!rule.id.isEmpty())
            ok = fw->removeRule(rule.id);
        if (ok) {
            rule.id.clear();
            ok = fw->addRule(rule);
        }
    }

    if (!ok)
        QMessageBox::warning(
            nullptr,
            QStringLiteral("Operation Failed"),
            fw->lastError());

    return ok ? 0 : 1;
}

static FirewallRule loadRuleFromFile(const QString &path)
{
    FirewallRule rule;
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return rule;

    QDataStream in(&file);
    int version = 0;
    int dir = 0, act = 0, proto = 0;

    in >> version;

    if (version >= 0x02) {
        in >> rule.id;
    }

    in >> rule.name >> rule.description >> rule.applicationPath
       >> dir >> act >> proto
       >> rule.localPorts >> rule.remotePorts >> rule.remoteAddresses
       >> rule.enabled;

    rule.direction = static_cast<FirewallRule::Direction>(dir);
    rule.action = static_cast<FirewallRule::Action>(act);
    rule.protocol = static_cast<FirewallRule::Protocol>(proto);

    return rule;
}
