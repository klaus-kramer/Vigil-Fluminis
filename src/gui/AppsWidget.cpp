// Copyright (c) 2026 Klaus Kramer - Licensed under the MIT License

#include "AppsWidget.h"
#include "core/IFirewall.h"
#include "core/KnownMalwareDb.h"
#include "core/SignatureChecker.h"
#include "core/RiskAnalyzer.h"
#include "core/FileAnalyzer.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QFont>
#include <QFileInfo>
#include <QLineEdit>
#include <QColor>
#include <QMessageBox>
#include <QMenu>
#include <QProgressDialog>
#include <QApplication>
#include <algorithm>
#include "core/AiAssistant.h"
#include "core/RiskAnalyzer.h"
#include "gui/AiResultDialog.h"

AppsWidget::AppsWidget(IFirewall *firewall, QWidget *parent)
    : QWidget(parent), m_firewall(firewall)
{
    setupUi();
}

AppsWidget::~AppsWidget() = default;

void AppsWidget::setupUi()
{
    auto root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    auto topBar = new QWidget;
    auto topLayout = new QHBoxLayout(topBar);
    topLayout->setContentsMargins(4, 4, 4, 4);

    auto backBtn = new QPushButton(QStringLiteral("<< Dashboard"));
    backBtn->setCursor(Qt::PointingHandCursor);
    connect(backBtn, &QPushButton::clicked, this, &AppsWidget::backToOverview);
    m_checkRepBtn = new QPushButton(QStringLiteral("Check All Apps"));
    m_checkRepBtn->setCursor(Qt::PointingHandCursor);
    connect(m_checkRepBtn, &QPushButton::clicked, this, &AppsWidget::checkAllApps);
    topLayout->addWidget(m_checkRepBtn);

    m_checkSigBtn = new QPushButton(QStringLiteral("Check Signatures"));
    m_checkSigBtn->setCursor(Qt::PointingHandCursor);
    connect(m_checkSigBtn, &QPushButton::clicked, this, &AppsWidget::checkAllSignatures);
    topLayout->addWidget(m_checkSigBtn);

    auto viewRulesBtn = new QPushButton(QStringLiteral("View Rules"));
    viewRulesBtn->setCursor(Qt::PointingHandCursor);
    connect(viewRulesBtn, &QPushButton::clicked, this, [this]() {
        int row = m_table->currentRow();
        if (row < 0) return;
        auto item = m_table->item(row, 0);
        if (item)
            emit showRulesForApp(item->data(Qt::UserRole).toString());
    });
    topLayout->addWidget(viewRulesBtn);

    m_askAiBtn = new QPushButton(QStringLiteral("Ask AI"));
    m_askAiBtn->setCursor(Qt::PointingHandCursor);
    m_askAiBtn->setEnabled(false);
    connect(m_askAiBtn, &QPushButton::clicked, this, &AppsWidget::onAskAi);
    topLayout->addWidget(m_askAiBtn);

    topLayout->addStretch();

    auto pageTitle = new QLabel(QStringLiteral("Application Rules"));
    QFont titleFont = pageTitle->font();
    titleFont.setPointSize(14);
    titleFont.setBold(true);
    pageTitle->setFont(titleFont);
    topLayout->addWidget(pageTitle);
    topLayout->addStretch();

    root->addWidget(topBar);

    auto searchBar = new QWidget;
    auto searchLayout = new QHBoxLayout(searchBar);
    searchLayout->setContentsMargins(4, 2, 4, 2);
    auto searchEdit = new QLineEdit;
    searchEdit->setPlaceholderText(QStringLiteral("Filter applications..."));
    searchEdit->setClearButtonEnabled(true);
    searchLayout->addWidget(new QLabel(QStringLiteral("Search:")), 0);
    searchLayout->addWidget(searchEdit, 1);
    root->addWidget(searchBar);

    connect(searchEdit, &QLineEdit::textChanged, this, [this](const QString &text) {
        for (int i = 0; i < m_table->rowCount(); ++i) {
            auto item = m_table->item(i, 0);
            bool match = !item || item->text().contains(text, Qt::CaseInsensitive);
            m_table->setRowHidden(i, !match);
        }
    });

    m_table = new QTableWidget;
    m_table->setColumnCount(13);
    m_table->setHorizontalHeaderLabels({
        QStringLiteral("Application"),
        QStringLiteral("Rules"),
        QStringLiteral("Allow"),
        QStringLiteral("Block"),
        QStringLiteral("Reputation"),
        QStringLiteral("Signature"),
        QStringLiteral("Risky Dir"),
        QStringLiteral("Permissive"),
        QStringLiteral("Company"),
        QStringLiteral("Orig. File"),
        QStringLiteral("Known Pub."),
        QStringLiteral("File Age"),
        QStringLiteral("Suspicious"),
    });
    m_table->horizontalHeader()->setStretchLastSection(false);
    m_table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(7, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(8, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(9, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(10, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(11, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(12, QHeaderView::ResizeToContents);
    m_table->verticalHeader()->hide();
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->setSortingEnabled(true);
    connect(m_table, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        auto item = m_table->item(row, 0);
        if (item)
            emit showRulesForApp(item->data(Qt::UserRole).toString());
    });
    root->addWidget(m_table, 1);

    auto bottomBar = new QWidget;
    auto bottomLayout = new QHBoxLayout(bottomBar);
    bottomLayout->setContentsMargins(4, 4, 4, 4);

    m_statusLabel = new QLabel;
    bottomLayout->addWidget(m_statusLabel);
    bottomLayout->addStretch();

    bottomLayout->addWidget(backBtn);
    root->addWidget(bottomBar);

    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_table, &QWidget::customContextMenuRequested, this, &AppsWidget::onTableContextMenu);

    connect(m_table, &QTableWidget::itemSelectionChanged, this, [this]() {
        m_askAiBtn->setEnabled(m_table->currentRow() >= 0 && AiAssistant::isModelLoaded());
    });
}

void AppsWidget::refresh()
{
    if (!m_firewall)
        return;

    auto rules = m_firewall->rules();
    auto apps = buildAppList(rules);

    std::sort(apps.begin(), apps.end(), [](const AppInfo &a, const AppInfo &b) {
        return suspiciousScore(a) > suspiciousScore(b);
    });

    m_table->setRowCount(apps.size());
    m_table->setUpdatesEnabled(false);
    m_table->setSortingEnabled(false);

    int totalRules = 0;
    for (int i = 0; i < apps.size(); ++i) {
        const auto &app = apps[i];
        totalRules += app.total;

        auto nameItem = new QTableWidgetItem(app.name.isEmpty()
            ? QStringLiteral("(system rules / no app)")
            : app.name);
        nameItem->setData(Qt::UserRole, app.path);
        QFont f = nameItem->font();
        if (!app.path.isEmpty())
            f.setBold(true);
        nameItem->setFont(f);
        nameItem->setToolTip(app.path.isEmpty()
            ? QStringLiteral("Rules not associated with a specific application")
            : app.path);
        m_table->setItem(i, 0, nameItem);
        m_table->setItem(i, 1, new QTableWidgetItem(QString::number(app.total)));
        m_table->setItem(i, 2, new QTableWidgetItem(QString::number(app.allow)));
        m_table->setItem(i, 3, new QTableWidgetItem(QString::number(app.block)));

        auto repItem = new QTableWidgetItem;
        applyRepToItem(repItem, app.repResult);
        m_table->setItem(i, 4, repItem);

        auto sigItem = new QTableWidgetItem;
        applySigToItem(sigItem, app.sigResult);
        m_table->setItem(i, 5, sigItem);

        auto dirItem = new QTableWidgetItem;
        applyDirToItem(dirItem, app.dirInfo);
        m_table->setItem(i, 6, dirItem);

        auto permItem = new QTableWidgetItem;
        applyPermissiveToItem(permItem, app.permissiveInfo);
        m_table->setItem(i, 7, permItem);

        auto companyItem = new QTableWidgetItem;
        applyCompanyToItem(companyItem, app.fileInfo);
        m_table->setItem(i, 8, companyItem);

        auto origItem = new QTableWidgetItem;
        applyOrigFileToItem(origItem, app);
        m_table->setItem(i, 9, origItem);

        auto knownPubItem = new QTableWidgetItem;
        applyKnownPubToItem(knownPubItem, app.sigResult);
        m_table->setItem(i, 10, knownPubItem);

        auto ageItem = new QTableWidgetItem;
        applyAgeToItem(ageItem, app.fileInfo);
        m_table->setItem(i, 11, ageItem);

        updateSuspiciousRow(i, app);
    }

    m_statusLabel->setText(
        QStringLiteral("Applications: %1 | Total rules: %2")
            .arg(apps.size()).arg(totalRules));

    m_table->setUpdatesEnabled(true);
    m_table->setSortingEnabled(true);
    computeTopSuspiciousApps();
}

void AppsWidget::updateAiButtonState()
{
    m_askAiBtn->setEnabled(m_table->currentRow() >= 0 && AiAssistant::isModelLoaded());
}

QVector<AppsWidget::AppInfo> AppsWidget::buildAppList(const QVector<FirewallRule> &rules)
{
    QMap<QString, AppInfo> appMap;

    for (const auto &r : rules) {
        QString key = r.applicationPath;
        auto &info = appMap[key];
        info.path = key;
        if (info.name.isEmpty() && !key.isEmpty())
            info.name = QFileInfo(key).fileName();
        ++info.total;
        if (r.action == FirewallRule::Action::Allow)
            ++info.allow;
        else
            ++info.block;

        QString perm = RiskAnalyzer::permissiveRuleInfo(r);
        if (!perm.isEmpty()) {
            if (info.permissiveInfo.isEmpty())
                info.permissiveInfo = perm;
            else
                info.permissiveInfo += QStringLiteral(" | ") + perm;
        }
        if (!key.isEmpty() && !m_repCache.contains(key)) {
            auto res = KnownMalwareDb::checkApp(key);
            m_repCache.insert(key, res);
        }
    }

    QVector<AppInfo> result;
    for (auto it = appMap.begin(); it != appMap.end(); ++it) {
        auto &info = it.value();
        info.repResult = m_repCache.value(info.path);
        info.sigResult = m_sigCache.value(info.path);
        info.dirInfo = RiskAnalyzer::suspiciousPathInfo(info.path);
        if (!info.path.isEmpty() && !m_fileInfoCache.contains(info.path)) {
            m_fileInfoCache.insert(info.path, FileAnalyzer::analyze(info.path));
        }
        info.fileInfo = m_fileInfoCache.value(info.path);
        result.append(info);
    }

    return result;
}

void AppsWidget::checkAllApps()
{
    m_repCache.clear();

    int total = 0, clean = 0, risky = 0;

    for (int i = 0; i < m_table->rowCount(); ++i) {
        auto nameItem = m_table->item(i, 0);
        if (!nameItem) continue;
        QString path = nameItem->data(Qt::UserRole).toString();
        if (path.isEmpty()) continue;

        auto res = KnownMalwareDb::checkApp(path);
        m_repCache.insert(path, res);

        auto repItem = m_table->item(i, 4);
        applyRepToItem(repItem, res);

        auto sigItem = m_table->item(i, 5);
        auto dirItem = m_table->item(i, 6);
        auto permItem = m_table->item(i, 7);

        AppInfo app;
        app.path = path;
        app.repResult = res;
        app.sigResult = m_sigCache.value(path);
        app.fileInfo = m_fileInfoCache.value(path);
        if (dirItem && dirItem->text() == QStringLiteral("Warning"))
            app.dirInfo = dirItem->toolTip();
        if (permItem && permItem->text() == QStringLiteral("Warning"))
            app.permissiveInfo = permItem->toolTip();

        updateSuspiciousRow(i, app);

        ++total;
        if (res.status == MalwareResult::Clean)
            ++clean;
        else
            ++risky;
    }

    computeTopSuspiciousApps();

    QMessageBox msgBox(this);
    msgBox.setWindowTitle(QStringLiteral("App Check Complete"));
    msgBox.setText(QStringLiteral("Check All Apps — Results"));
    msgBox.setInformativeText(
        QStringLiteral("Total apps checked: %1\nClean (unflagged): %2\nRisky (suspicious/malicious): %3")
            .arg(total).arg(clean).arg(risky));
    msgBox.setIcon(QMessageBox::Information);
    msgBox.setStandardButtons(QMessageBox::Ok);
    msgBox.exec();
}

void AppsWidget::checkAllSignatures()
{
    m_sigCache.clear();
    m_table->setUpdatesEnabled(false);
    m_table->setSortingEnabled(false);

    int count = 0;
    for (int i = 0; i < m_table->rowCount(); ++i) {
        auto nameItem = m_table->item(i, 0);
        if (!nameItem) continue;
        if (!nameItem->data(Qt::UserRole).toString().isEmpty())
            ++count;
    }

    QProgressDialog progress(QStringLiteral("Checking digital signatures..."),
        QString(), 0, count, this);
    progress.setWindowTitle(QStringLiteral("Signature Check"));
    progress.setWindowModality(Qt::WindowModal);
    progress.setMinimumDuration(0);
    QApplication::processEvents();

    int done = 0, verified = 0, unsigned_ = 0, untrusted = 0, errors = 0;

    for (int i = 0; i < m_table->rowCount(); ++i) {
        auto nameItem = m_table->item(i, 0);
        if (!nameItem) continue;
        QString path = nameItem->data(Qt::UserRole).toString();
        if (path.isEmpty()) continue;

        if (progress.wasCanceled())
            break;

        progress.setLabelText(
            QStringLiteral("Checking: %1").arg(nameItem->text()));
        progress.setValue(done);
        QApplication::processEvents();

        auto res = SignatureChecker::check(path);
        m_sigCache.insert(path, res);

        auto sigItem = m_table->item(i, 5);
        applySigToItem(sigItem, res);

        ++done;
        switch (res.status) {
        case SignatureResult::Verified:       ++verified; break;
        case SignatureResult::Unsigned:       ++unsigned_; break;
        case SignatureResult::SelfSigned:
        case SignatureResult::Expired:
        case SignatureResult::Revoked:
        case SignatureResult::UntrustedRoot:  ++untrusted; break;
        case SignatureResult::Error:          ++errors; break;
        }
    }

    progress.close();

    m_table->setSortingEnabled(true);
    m_table->setUpdatesEnabled(true);

    for (int i = 0; i < m_table->rowCount(); ++i) {
        auto nameItem = m_table->item(i, 0);
        if (!nameItem) continue;
        QString path = nameItem->data(Qt::UserRole).toString();
        if (path.isEmpty()) continue;

        SignatureResult sig = m_sigCache.value(path);
        MalwareResult rep = m_repCache.value(path);
        FileInfoResult fi = m_fileInfoCache.value(path);

        auto knownItem = m_table->item(i, 10);
        if (knownItem)
            applyKnownPubToItem(knownItem, sig);

        auto *dirCell = m_table->item(i, 6);
        auto *permCell = m_table->item(i, 7);

        AppInfo app;
        app.path = path;
        app.sigResult = sig;
        app.repResult = rep;
        app.fileInfo = fi;
        app.dirInfo = (dirCell && dirCell->text() == QStringLiteral("Warning"))
            ? dirCell->toolTip() : QString();
        app.permissiveInfo = (permCell && permCell->text() == QStringLiteral("Warning"))
            ? permCell->toolTip() : QString();

        updateSuspiciousRow(i, app);
    }

    computeTopSuspiciousApps();

    QMessageBox msgBox(this);
    msgBox.setWindowTitle(QStringLiteral("Signature Check Complete"));
    msgBox.setText(QStringLiteral("Check Signatures — Results"));
    msgBox.setInformativeText(
        QStringLiteral("Total apps checked: %1\n"
                       "Verified (signed):   %2\n"
                       "Unsigned:           %3\n"
                       "Untrusted / other:  %4\n"
                       "Error (unverifiable): %5")
            .arg(done).arg(verified).arg(unsigned_).arg(untrusted).arg(errors));
    msgBox.setIcon(QMessageBox::Information);
    msgBox.setStandardButtons(QMessageBox::Ok);
    msgBox.exec();
}

void AppsWidget::applySigToItem(QTableWidgetItem *item, const SignatureResult &res)
{
    if (!item) return;

    item->setText(res.statusText());
    item->setToolTip(res.statusTooltip());

    switch (res.status) {
    case SignatureResult::Verified:
        item->setForeground(QColor(0x2E, 0x7D, 0x32));
        break;
    case SignatureResult::Unsigned:
    case SignatureResult::SelfSigned:
    case SignatureResult::Expired:
    case SignatureResult::Revoked:
    case SignatureResult::UntrustedRoot:
        item->setForeground(QColor(0xCC, 0x88, 0x00));
        break;
    case SignatureResult::Error:
        item->setForeground(QColor(Qt::red));
        break;
    default:
        item->setForeground(QColor());
        break;
    }
}

void AppsWidget::applyRepToItem(QTableWidgetItem *item, const MalwareResult &res)
{
    if (!item) return;

    if (res.status == MalwareResult::Malicious) {
        item->setText(QStringLiteral("Malicious"));
        item->setToolTip(res.details);
        item->setForeground(QColor(Qt::red));
        QFont rf = item->font();
        rf.setBold(true);
        item->setFont(rf);
    } else if (res.status == MalwareResult::Suspicious) {
        item->setText(QStringLiteral("Suspicious"));
        item->setToolTip(res.details);
        item->setForeground(QColor(0xCC, 0x88, 0x00));
        QFont rf = item->font();
        rf.setBold(true);
        item->setFont(rf);
    } else if (res.status == MalwareResult::Clean) {
        item->setText(QStringLiteral("Clean"));
        item->setToolTip(res.details);
        item->setForeground(QColor());
        QFont rf = item->font();
        rf.setBold(false);
        item->setFont(rf);
    } else {
        item->setText(QStringLiteral("Not checked"));
        item->setToolTip(QStringLiteral("Click 'Check All Apps' to scan"));
        item->setForeground(QColor());
        QFont rf = item->font();
        rf.setBold(false);
        item->setFont(rf);
    }
}

void AppsWidget::applyPermissiveToItem(QTableWidgetItem *item, const QString &permissiveInfo)
{
    if (!item) return;

    if (permissiveInfo.isEmpty()) {
        item->setText(QStringLiteral("OK"));
        item->setToolTip(QStringLiteral("No overly permissive rules"));
        item->setForeground(QColor(0x2E, 0x7D, 0x32));
    } else {
        item->setText(QStringLiteral("Warning"));
        item->setToolTip(permissiveInfo);
        item->setForeground(QColor(0xCC, 0x88, 0x00));
    }
}

static QString repStatusText(MalwareResult::Status s)
{
    switch (s) {
    case MalwareResult::Clean:      return QStringLiteral("Clean");
    case MalwareResult::Suspicious: return QStringLiteral("Suspicious");
    case MalwareResult::Malicious:  return QStringLiteral("Malicious");
    default:                        return QStringLiteral("Unknown");
    }
}

void AppsWidget::computeTopSuspiciousApps()
{
    QVector<QPair<int, QString>> entries;
    for (int i = 0; i < m_table->rowCount(); ++i) {
        auto nameItem = m_table->item(i, 0);
        auto suspItem = m_table->item(i, 12);
        if (!nameItem || !suspItem) continue;
        QString path = nameItem->data(Qt::UserRole).toString();
        if (path.isEmpty()) continue;
        bool ok = false;
        int score = suspItem->text().toInt(&ok);
        if (ok)
            entries.append({score, nameItem->text()});
    }

    std::sort(entries.begin(), entries.end(), [](const auto &a, const auto &b) {
        return a.first > b.first;
    });

    QStringList names;
    QList<int> scores;
    for (int i = 0; i < qMin(3, entries.size()); ++i) {
        names.append(entries[i].second);
        scores.append(entries[i].first);
    }

    emit topSuspiciousAppsUpdated(names, scores);
}

void AppsWidget::onAskAi()
{
    if (!AiAssistant::isModelLoaded()) {
        QMessageBox::information(this, QStringLiteral("AI Assistant"),
            QStringLiteral("No AI model loaded.\n\n"
                           "Go to Options → AI Settings to configure the model path."));
        return;
    }

    int row = m_table->currentRow();
    if (row < 0) {
        QMessageBox::information(this, QStringLiteral("AI Assistant"),
            QStringLiteral("Please select an application first."));
        return;
    }

    auto nameItem = m_table->item(row, 0);
    if (!nameItem) return;

    QString appPath = nameItem->data(Qt::UserRole).toString();
    if (appPath.isEmpty()) {
        auto rules = m_firewall ? m_firewall->rules() : QVector<FirewallRule>();
        QVector<FirewallRule> matched;
        for (const auto &r : rules) {
            if (r.applicationPath.isEmpty()) {
                matched.append(r);
            }
        }
        if (matched.isEmpty()) return;
        std::sort(matched.begin(), matched.end(), [](const FirewallRule &a, const FirewallRule &b) {
            return RiskAnalyzer::analyze(a).score > RiskAnalyzer::analyze(b).score;
        });
        FirewallRule rule = matched.first();
        RiskResult risk = RiskAnalyzer::analyze(rule);
        auto dialog = new AiResultDialog(rule, risk, this);
        dialog->open();
        return;
    }

    auto rules = m_firewall ? m_firewall->rules() : QVector<FirewallRule>();
    QVector<FirewallRule> matched;
    for (const auto &r : rules) {
        if (r.applicationPath.compare(appPath, Qt::CaseInsensitive) == 0) {
            matched.append(r);
        }
    }
    if (matched.isEmpty()) return;

    std::sort(matched.begin(), matched.end(), [](const FirewallRule &a, const FirewallRule &b) {
        return RiskAnalyzer::analyze(a).score > RiskAnalyzer::analyze(b).score;
    });
    FirewallRule rule = matched.first();
    RiskResult risk = RiskAnalyzer::analyze(rule);
    auto dialog = new AiResultDialog(rule, risk, this);
    dialog->open();
}

void AppsWidget::onTableContextMenu(const QPoint &pos)
{
    auto idx = m_table->indexAt(pos);
    if (!idx.isValid()) return;

    bool hasModel = AiAssistant::isModelLoaded();

    QMenu menu(this);
    QAction *askAiAction = menu.addAction(QStringLiteral("Ask AI"));
    askAiAction->setEnabled(hasModel);
    connect(askAiAction, &QAction::triggered, this, &AppsWidget::onAskAi);

    menu.addSeparator();

    QAction *viewAction = menu.addAction(QStringLiteral("View Rules"));
    connect(viewAction, &QAction::triggered, this, [this]() {
        int row = m_table->currentRow();
        if (row < 0) return;
        auto item = m_table->item(row, 0);
        if (item)
            emit showRulesForApp(item->data(Qt::UserRole).toString());
    });

    menu.exec(m_table->viewport()->mapToGlobal(pos));
}

int AppsWidget::suspiciousScore(const AppInfo &app)
{
    int score = 0;
    if (app.repResult.status != MalwareResult::Clean && app.repResult.status != MalwareResult::Unknown)
        ++score;
    if (app.sigResult.status != SignatureResult::Verified)
        ++score;
    if (!app.dirInfo.isEmpty())
        ++score;
    if (!app.permissiveInfo.isEmpty())
        ++score;
    if (!app.fileInfo.hasVersionInfo || app.fileInfo.companyName.isEmpty())
        ++score;
    if (app.fileInfo.hasVersionInfo && !app.fileInfo.originalFilename.isEmpty()) {
        QString fn = QFileInfo(app.path).fileName();
        if (fn.compare(app.fileInfo.originalFilename, Qt::CaseInsensitive) != 0)
            ++score;
    }
    if (app.sigResult.isTrusted() && !FileAnalyzer::isKnownPublisher(app.sigResult.publisher))
        ++score;
    if (app.fileInfo.hasVersionInfo && app.fileInfo.lastModified.isValid()) {
        qint64 days = app.fileInfo.lastModified.daysTo(QDateTime::currentDateTime());
        if (days < 30 || days > 365 * 4)
            ++score;
    }
    return score;
}

void AppsWidget::updateSuspiciousRow(int row, const AppInfo &app)
{
    int suspScore = suspiciousScore(app);

    auto *suspItem = m_table->item(row, 12);
    if (!suspItem) {
        suspItem = new QTableWidgetItem;
        m_table->setItem(row, 12, suspItem);
    }
    suspItem->setText(QString::number(suspScore));
    suspItem->setToolTip(suspiciousTooltip(app));
    if (suspScore == 0)
        suspItem->setForeground(QColor(0x2E, 0x7D, 0x32));
    else if (suspScore == 1)
        suspItem->setForeground(QColor(0xCC, 0x88, 0x00));
    else
        suspItem->setForeground(QColor(Qt::red));
    QFont sf = suspItem->font();
    sf.setBold(suspScore >= 2);
    suspItem->setFont(sf);
}

QString AppsWidget::suspiciousTooltip(const AppInfo &app) const
{
    QStringList factors;
    if (app.repResult.status != MalwareResult::Clean && app.repResult.status != MalwareResult::Unknown)
        factors.append(QStringLiteral("+1 Reputation (%1)").arg(repStatusText(app.repResult.status)));
    if (app.sigResult.status != SignatureResult::Verified)
        factors.append(QStringLiteral("+1 Signature (%1)").arg(app.sigResult.statusText()));
    if (!app.dirInfo.isEmpty())
        factors.append(QStringLiteral("+1 Directory (%1)").arg(app.dirInfo));
    if (!app.permissiveInfo.isEmpty())
        factors.append(QStringLiteral("+1 Permissive (%1)").arg(app.permissiveInfo));
    if (!app.fileInfo.hasVersionInfo || app.fileInfo.companyName.isEmpty()) {
        if (!app.fileInfo.hasVersionInfo)
            factors.append(QStringLiteral("+1 No Company (no VERSIONINFO)"));
        else
            factors.append(QStringLiteral("+1 No Company (empty)"));
    }
    if (app.fileInfo.hasVersionInfo && !app.fileInfo.originalFilename.isEmpty()) {
        QString fn = QFileInfo(app.path).fileName();
        if (fn.compare(app.fileInfo.originalFilename, Qt::CaseInsensitive) != 0)
            factors.append(QStringLiteral("+1 Orig. File differs (%1)").arg(app.fileInfo.originalFilename));
    }
    if (app.sigResult.isTrusted() && !FileAnalyzer::isKnownPublisher(app.sigResult.publisher))
        factors.append(QStringLiteral("+1 Unknown Publisher (%1)").arg(app.sigResult.publisher));

    if (app.fileInfo.hasVersionInfo && app.fileInfo.lastModified.isValid()) {
        qint64 days = app.fileInfo.lastModified.daysTo(QDateTime::currentDateTime());
        if (days < 30)
            factors.append(QStringLiteral("+1 File age (%1 days old, recent)").arg(days));
        else if (days > 365 * 3)
            factors.append(QStringLiteral("+1 File age (%1 days old, > 4 years)").arg(days));
    }

    return factors.isEmpty()
        ? QStringLiteral("No suspicious indicators")
        : factors.join(QStringLiteral("\n"));
}

void AppsWidget::applyCompanyToItem(QTableWidgetItem *item, const FileInfoResult &fi)
{
    if (!item) return;

    if (fi.hasVersionInfo) {
        if (fi.companyName.isEmpty()) {
            item->setText(QStringLiteral("None"));
            item->setToolTip(QStringLiteral("VERSIONINFO present but CompanyName is empty"));
            item->setForeground(QColor(0xCC, 0x88, 0x00));
        } else {
            QFontMetrics fm(item->font());
            item->setText(fm.elidedText(fi.companyName, Qt::ElideRight, 170));
            item->setToolTip(fi.companyName);
            item->setForeground(QColor(0x2E, 0x7D, 0x32));
        }
    } else {
        item->setText(QStringLiteral("N/A"));
        item->setToolTip(QStringLiteral("File has no VERSIONINFO resources"));
        item->setForeground(QColor());
    }
}

void AppsWidget::applyOrigFileToItem(QTableWidgetItem *item, const AppInfo &app)
{
    if (!item) return;

    if (!app.fileInfo.hasVersionInfo || app.fileInfo.originalFilename.isEmpty()) {
        item->setText(QStringLiteral("N/A"));
        item->setToolTip(QStringLiteral("No OriginalFilename in VERSIONINFO"));
        item->setForeground(QColor());
    } else {
        QString fn = QFileInfo(app.path).fileName();
        if (fn.compare(app.fileInfo.originalFilename, Qt::CaseInsensitive) == 0) {
            item->setText(QStringLiteral("Matches"));
            item->setToolTip(QStringLiteral("File name matches OriginalFilename"));
            item->setForeground(QColor(0x2E, 0x7D, 0x32));
        } else {
            item->setText(QStringLiteral("Differs"));
            item->setToolTip(QStringLiteral("OriginalFilename: %1").arg(app.fileInfo.originalFilename));
            item->setForeground(QColor(Qt::red));
        }
    }
}

void AppsWidget::applyKnownPubToItem(QTableWidgetItem *item, const SignatureResult &sig)
{
    if (!item) return;

    if (sig.status == SignatureResult::NotChecked) {
        item->setText(QStringLiteral("Not checked"));
        item->setToolTip(QStringLiteral("Run signature check first"));
        item->setForeground(QColor());
    } else if (sig.status == SignatureResult::Verified) {
        if (FileAnalyzer::isKnownPublisher(sig.publisher)) {
            item->setText(QStringLiteral("Yes"));
            item->setToolTip(QStringLiteral("Known publisher: %1").arg(sig.publisher));
            item->setForeground(QColor(0x2E, 0x7D, 0x32));
        } else {
            item->setText(QStringLiteral("No"));
            item->setToolTip(QStringLiteral("Unknown publisher: %1").arg(sig.publisher));
            item->setForeground(QColor(0xCC, 0x88, 0x00));
        }
    } else {
        item->setText(QStringLiteral("N/A"));
        item->setToolTip(QStringLiteral("Not signed"));
        item->setForeground(QColor());
    }
}

void AppsWidget::applyDirToItem(QTableWidgetItem *item, const QString &dirInfo)
{
    if (!item) return;

    if (dirInfo.isEmpty()) {
        item->setText(QStringLiteral("OK"));
        item->setToolTip(QStringLiteral("Application runs from a standard directory"));
        item->setForeground(QColor(0x2E, 0x7D, 0x32));
    } else {
        item->setText(QStringLiteral("Warning"));
        item->setToolTip(dirInfo);
        item->setForeground(QColor(0xCC, 0x88, 0x00));
    }
}

void AppsWidget::applyAgeToItem(QTableWidgetItem *item, const FileInfoResult &fi)
{
    if (!item) return;

    if (!fi.hasVersionInfo || !fi.lastModified.isValid()) {
        item->setText(QStringLiteral("N/A"));
        item->setToolTip(QStringLiteral("No file timestamp available"));
        item->setForeground(QColor());
        return;
    }

    qint64 days = fi.lastModified.daysTo(QDateTime::currentDateTime());
    if (days < 0) days = 0;

    if (days < 30) {
        item->setText(QStringLiteral("Recent"));
        item->setToolTip(QStringLiteral("File is %1 days old").arg(days));
        item->setForeground(QColor(0xCC, 0x88, 0x00));
    } else if (days > 365 * 4) {
        item->setText(QStringLiteral("Old"));
        item->setToolTip(QStringLiteral("File is %1 days old (> 4 years)").arg(days));
        item->setForeground(QColor(0xCC, 0x88, 0x00));
    } else {
        item->setText(QStringLiteral("OK"));
        item->setToolTip(QStringLiteral("File is %1 days old").arg(days));
        item->setForeground(QColor(0x2E, 0x7D, 0x32));
    }
}
