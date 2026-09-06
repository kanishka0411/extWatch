#include "app/trayapp.h"

#include <QAction>
#include <QApplication>
#include <QIcon>
#include <QMenu>
#include <QPixmap>
#include <QSystemTrayIcon>
#include <QDebug>
#include <QtConcurrent/QtConcurrent>

#include "app/appsettings.h"
#include "app/companiondialog.h"
#include "app/mainwindow.h"
#include "app/settingsdialog.h"
#include "core/database.h"
#include "core/discovery.h"
#include "core/rules.h"

namespace extwatch {

namespace {

QIcon trayIcon(bool alert) {
    QIcon icon(alert ? QStringLiteral(":/app/icons/tray-alert.svg") : QStringLiteral(":/app/icons/tray.svg"));
    icon.setIsMask(true);  // monochrome template on the macOS menu bar
    return icon;
}

int severityRank(const QString& s) {
    if (s == QStringLiteral("high")) return 3;
    if (s == QStringLiteral("medium")) return 2;
    if (s == QStringLiteral("low")) return 1;
    return 0;
}

}  // namespace

TrayApp::TrayApp(QString dataDir, QObject* parent) : QObject(parent), m_dataDir(std::move(dataDir)) {
    m_watcher = new QFutureWatcher<ScanResult>(this);
    connect(m_watcher, &QFutureWatcher<ScanResult>::finished, this, &TrayApp::onScanFinished);
    m_fsWatcher = new ProfileWatcher(this);
    connect(m_fsWatcher, &ProfileWatcher::changed, this, [this](const QStringList&) { rescan(); });
    connect(&m_periodic, &QTimer::timeout, this, &TrayApp::rescan);
    m_storeWatcher = new QFutureWatcher<StoreTrackingResult>(this);
    connect(m_storeWatcher, &QFutureWatcher<StoreTrackingResult>::finished, this, &TrayApp::onStoreTrackingFinished);
    m_companion = new CompanionServer(this);
    m_companionRescan.setSingleShot(true);
    m_companionRescan.setInterval(2500);
    connect(&m_companionRescan, &QTimer::timeout, this, &TrayApp::rescan);
    connect(m_companion, &CompanionServer::connectionsChanged, this, &TrayApp::pushCompanionStatus);
    connect(m_companion, &CompanionServer::extensionEvent, this,
            [this](const QString&, const QString&, const QString&, const QString&) { m_companionRescan.start(); });
    applySettings();
}

TrayApp::~TrayApp() {
    if (m_watcher->isRunning()) {
        m_watcher->waitForFinished();
    }
    if (m_storeWatcher->isRunning()) {
        m_storeWatcher->waitForFinished();
    }
}

bool TrayApp::start(QString* error) {
    QString ipcError;
    if (!m_companion->start(&ipcError)) {
        qWarning("ExtWatch: companion server not started: %s", qPrintable(ipcError));
    }
    m_tray = new QSystemTrayIcon(trayIcon(false), this);
    buildMenu();
    m_tray->setContextMenu(m_menu);
    m_tray->setToolTip(QStringLiteral("ExtWatch"));
    connect(m_tray, &QSystemTrayIcon::activated, this, [this](QSystemTrayIcon::ActivationReason r) {
        if (r == QSystemTrayIcon::Trigger || r == QSystemTrayIcon::DoubleClick) {
            showWindow();
        }
    });
    connect(m_tray, &QSystemTrayIcon::messageClicked, this, &TrayApp::showWindow);
    if (QSystemTrayIcon::isSystemTrayAvailable()) {
        m_tray->show();
    } else {
        if (error) {
            *error = QStringLiteral("no system tray available");
        }
        showWindow();
    }
    if (m_showOnStart || !AppSettings::firstRunDone()) {
        showWindow();
        AppSettings::setFirstRunDone(true);
    }
    armWatcherFromDiscovery();
    rescan();
    return true;
}

void TrayApp::armWatcherFromDiscovery() {
    QStringList profiles;
    for (const DiscoveredBrowser& b : discoverBrowsers(scanOptions().candidates)) {
        for (const Profile& p : b.profiles) {
            profiles.append(p.path);
        }
    }
    m_fsWatcher->setProfiles(profiles);
}

void TrayApp::buildMenu() {
    m_menu = new QMenu();
    m_statusAction = m_menu->addAction(QStringLiteral("Scanning…"));
    m_statusAction->setEnabled(false);
    m_menu->addSeparator();
    m_recentMenu = m_menu->addMenu(QStringLiteral("Recent changes"));
    m_recentMenu->setEnabled(false);
    m_menu->addSeparator();
    QAction* open = m_menu->addAction(QStringLiteral("Open ExtWatch"));
    connect(open, &QAction::triggered, this, &TrayApp::showWindow);
    m_rescanAction = m_menu->addAction(QStringLiteral("Rescan now"));
    connect(m_rescanAction, &QAction::triggered, this, &TrayApp::rescan);
    QAction* settings = m_menu->addAction(QStringLiteral("Settings…"));
    connect(settings, &QAction::triggered, this, &TrayApp::openSettings);
    QAction* companion = m_menu->addAction(QStringLiteral("Set up companion extension…"));
    connect(companion, &QAction::triggered, this, &TrayApp::openCompanionSetup);
    m_menu->addSeparator();
    QAction* quit = m_menu->addAction(QStringLiteral("Quit ExtWatch"));
    connect(quit, &QAction::triggered, qApp, &QApplication::quit);
}

ScanOptions TrayApp::scanOptions() const {
    ScanOptions options;
    options.dataDir = m_dataDir;
    options.candidates = knownBrowserLocations();
    for (const QString& entry : AppSettings::extraUserDataDirs()) {
        const qsizetype eq = entry.indexOf(u'=');
        const QString kindId = eq > 0 ? entry.left(eq).trimmed() : QStringLiteral("chrome");
        const QString path = (eq > 0 ? entry.mid(eq + 1) : entry).trimmed();
        if (const auto kind = browserKindFromId(kindId); kind && !path.isEmpty()) {
            options.candidates.append({*kind, browserKindName(*kind) + QStringLiteral(" (custom)"), path});
        }
    }
    return options;
}

void TrayApp::applySettings() {
    m_periodic.setInterval(AppSettings::rescanIntervalMinutes() * 60 * 1000);
    if (!m_periodic.isActive()) {
        m_periodic.start();
    }
}

void TrayApp::rescan() {
    if (qEnvironmentVariableIsSet("EXTWATCH_DEBUG")) {
        qInfo() << "tray: rescan requested, scan running:" << m_watcher->isRunning();
    }
    if (m_watcher->isRunning()) {
        m_rescanQueued = true;
        return;
    }
    m_rescanAction->setEnabled(false);
    m_statusAction->setText(m_firstScan ? QStringLiteral("Scanning… (the first run analyzes every extension)")
                                        : QStringLiteral("Scanning…"));
    ScanOptions options = scanOptions();
    // Stored fingerprints (per-file size and mtime) make rescans cheap; every fourth scan and the
    // first one after launch re-hash every tree so a same-size, same-mtime overwrite is caught.
    options.forceHash = m_firstScan || m_scansSinceFullHash >= 3;
    m_scansSinceFullHash = options.forceHash ? 0 : m_scansSinceFullHash + 1;
    m_watcher->setFuture(QtConcurrent::run(runScan, options));
}

void TrayApp::onScanFinished() {
    m_lastResult = m_watcher->result();
    m_rescanAction->setEnabled(true);
    refreshStatus(m_lastResult);
    notifyChanges(m_lastResult);
    emit scanFinished(m_lastResult);

    QStringList profiles;
    for (const BrowserReport& b : m_lastResult.browsers) {
        for (const ProfileReport& p : b.profiles) {
            profiles.append(p.profile.path);
        }
    }
    m_fsWatcher->setProfiles(profiles);
    if (m_window) {
        m_window->setWatchStatus(QStringLiteral("watching %1 paths").arg(m_fsWatcher->watchedPathCount()));
    }

    if (m_firstScan && !m_screenshotPath.isEmpty()) {
        showWindow();
        Database db;
        if (db.open(databasePath(m_dataDir))) {
            for (const EventRow& e : db.recentEvents(20)) {
                if (e.kind == QStringLiteral("updated")) {
                    m_window->openEvent(e.id);
                    break;
                }
            }
        }
        const QString path = m_screenshotPath;
        QPointer<MainWindow> window = m_window;
        bool tabOk = false;
        const int tab = qEnvironmentVariableIntValue("EXTWATCH_SCREENSHOT_TAB", &tabOk);
        if (tabOk) {
            m_window->selectDetailTab(tab);
        }
        QTimer::singleShot(1500, this, [window, path]() {
            if (window) {
                window->grab().save(path);
            }
            qApp->quit();
        });
    }
    if (AppSettings::trackPublisher() && !m_storeWatcher->isRunning()) {
        const QString dataDir = m_dataDir;
        m_storeWatcher->setFuture(QtConcurrent::run([dataDir]() { return runStoreTracking(dataDir); }));
    }
    m_firstScan = false;
    if (m_rescanQueued) {
        m_rescanQueued = false;
        QTimer::singleShot(2000, this, &TrayApp::rescan);
    }
}

void TrayApp::refreshStatus(const ScanResult& result) {
    const QString status = QStringLiteral("%1 extensions in %2 profiles").arg(result.extensionCount()).arg(result.profileCount());
    m_statusAction->setText(status);
    m_tray->setToolTip(QStringLiteral("ExtWatch · ") + status);
    refreshRecentMenu();
}

void TrayApp::refreshRecentMenu() {
    m_recentMenu->clear();
    Database db;
    int unacknowledged = 0;
    int shown = 0;
    if (db.open(databasePath(m_dataDir))) {
        for (const EventRow& e : db.recentEvents(60)) {
            if (e.kind == QStringLiteral("baseline")) {
                continue;
            }
            if (!e.acknowledged) {
                unacknowledged++;
            }
            if (shown >= 10) {
                continue;
            }
            const std::optional<ExtensionRow> ext = db.extensionById(e.extensionId);
            QString label = ext ? ext->name : QStringLiteral("?");
            if (e.toVersionId) {
                if (const auto v = db.versionById(*e.toVersionId)) label += QStringLiteral(" → %1").arg(v->version);
            }
            if (!e.maxSeverity.isEmpty()) {
                label += QStringLiteral("  [%1]").arg(e.maxSeverity);
            }
            if (!e.acknowledged) {
                label += QStringLiteral("  •");
            }
            QAction* a = m_recentMenu->addAction(label);
            const qint64 id = e.id;
            connect(a, &QAction::triggered, this, [this, id]() { openEvent(id); });
            shown++;
        }
    }
    m_recentMenu->setEnabled(shown > 0);
    m_tray->setIcon(trayIcon(unacknowledged > 0));
}

void TrayApp::notifyChanges(const ScanResult& result) {
    const int threshold = AppSettings::notifyThreshold();
    QStringList minor;
    bool anyChange = false;
    for (const ScanEvent& e : result.events) {
        if (e.kind == QStringLiteral("baseline")) {
            continue;
        }
        anyChange = true;
        if (e.kind == QStringLiteral("updated") || e.kind == QStringLiteral("pending_version")) {
            if (severityRank(e.maxSeverity) < threshold) {
                continue;
            }
            QSystemTrayIcon::MessageIcon icon = QSystemTrayIcon::Information;
            if (e.maxSeverity == QStringLiteral("high")) {
                icon = QSystemTrayIcon::Critical;
            } else if (e.maxSeverity == QStringLiteral("medium")) {
                icon = QSystemTrayIcon::Warning;
            }
            QString body = e.findingsSummary.isEmpty() ? QStringLiteral("Click to review the diff.") : e.findingsSummary;
            if (e.kind == QStringLiteral("pending_version")) {
                body = QStringLiteral("Downloaded, activates when idle. ") + body;
            }
            m_tray->showMessage(e.headline(), body, icon, 15000);
        } else if (threshold == 0) {
            minor.append(e.summary());
        }
    }
    if (!minor.isEmpty()) {
        m_tray->showMessage(QStringLiteral("Extension changes"), minor.mid(0, 4).join(u'\n'), QSystemTrayIcon::Information, 8000);
    }
    if (!anyChange && m_firstScan && !result.events.isEmpty() && threshold == 0) {
        m_tray->showMessage(QStringLiteral("ExtWatch is watching"),
                            QStringLiteral("%1 extensions recorded as baseline. You will be notified when any of them changes.").arg(result.events.size()),
                            QSystemTrayIcon::Information, 6000);
    }
}

void TrayApp::showWindow() {
    if (!m_window) {
        m_window = new MainWindow(m_dataDir);
        m_window->setAttribute(Qt::WA_DeleteOnClose);
        connect(this, &TrayApp::scanFinished, m_window, &MainWindow::showScanResult);
        connect(m_window, &MainWindow::rescanRequested, this, &TrayApp::rescan);
        connect(m_window, &MainWindow::settingsChanged, this, &TrayApp::applySettings);
        connect(m_window, &MainWindow::eventAcknowledged, this, &TrayApp::refreshRecentMenu);
        connect(m_window, &MainWindow::toggleEnabledRequested, this, &TrayApp::toggleExtension);
        connect(m_window, &MainWindow::companionSetupRequested, this, &TrayApp::openCompanionSetup);
        m_window->setCompanionStatus(m_companion->connectionCount(), m_companion->connectedBrowsers());
        if (m_lastResult.scannedAt.isValid()) {
            m_window->showScanResult(m_lastResult);
            m_window->setWatchStatus(QStringLiteral("watching %1 paths").arg(m_fsWatcher->watchedPathCount()));
        }
    }
    m_window->show();
    m_window->raise();
    m_window->activateWindow();
}

void TrayApp::openEvent(qint64 eventId) {
    showWindow();
    m_window->openEvent(eventId);
}

void TrayApp::onStoreTrackingFinished() {
    const StoreTrackingResult r = m_storeWatcher->result();
    for (const StoreEvent& e : r.events) {
        m_tray->showMessage(e.extName, e.detail,
                            e.severity == QStringLiteral("high") ? QSystemTrayIcon::Critical : QSystemTrayIcon::Warning, 15000);
    }
    if (!r.events.isEmpty()) {
        refreshRecentMenu();
        if (m_window) {
            m_window->reloadTree();
        }
    }
}

void TrayApp::pushCompanionStatus() {
    if (m_window) {
        m_window->setCompanionStatus(m_companion->connectionCount(), m_companion->connectedBrowsers());
    }
}

void TrayApp::openCompanionSetup() {
    showWindow();
    CompanionDialog dialog(m_dataDir, m_companion, m_window);
    dialog.exec();
}

void TrayApp::toggleExtension(const CompanionServer::Target& target, bool enable) {
    QPointer<MainWindow> window = m_window;
    m_companion->setEnabled(target, enable, [this, window, enable](const QStringList& ok, const QStringList& failed) {
        QString text;
        if (!ok.isEmpty()) {
            text += QStringLiteral("%1 in %2.\n").arg(enable ? QStringLiteral("Enabled") : QStringLiteral("Disabled"), ok.join(QStringLiteral(", ")));
        }
        if (!failed.isEmpty()) {
            text += QStringLiteral("Problems: %1").arg(failed.join(QStringLiteral("; ")));
        }
        if (window) {
            window->showActionResult(enable ? QStringLiteral("Enable") : QStringLiteral("Disable"), text.trimmed(), ok.isEmpty());
        }
        m_companionRescan.start();
    });
}

void TrayApp::openSettings() {
    SettingsDialog dialog(m_dataDir, m_window);
    connect(&dialog, &SettingsDialog::settingsChanged, this, &TrayApp::applySettings);
    dialog.exec();
}

}  // namespace extwatch
