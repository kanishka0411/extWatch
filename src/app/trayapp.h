#pragma once

#include <QFutureWatcher>
#include <QObject>
#include <QPointer>
#include <QString>
#include <QTimer>

#include "core/companionserver.h"
#include "core/scanner.h"
#include "core/storetracker.h"
#include "core/watcher.h"

class QAction;
class QMenu;
class QSystemTrayIcon;

namespace extwatch {

class MainWindow;

// Owns the tray icon, the file-system watcher and the periodic rescan; runs scans on a worker
// thread and raises notifications for changes.
class TrayApp : public QObject {
    Q_OBJECT
public:
    explicit TrayApp(QString dataDir, QObject* parent = nullptr);
    ~TrayApp() override;

    bool start(QString* error);
    void setScreenshotPath(const QString& path) { m_screenshotPath = path; }
    void setShowWindowOnStart(bool show) { m_showOnStart = show; }

public slots:
    void rescan();
    void showWindow();
    void openEvent(qint64 eventId);
    void openSettings();
    void openCompanionSetup();
    void toggleExtension(const extwatch::CompanionServer::Target& target, bool enable);

signals:
    void scanFinished(const extwatch::ScanResult& result);

private slots:
    void onScanFinished();
    void onStoreTrackingFinished();
    void applySettings();
    void pushCompanionStatus();

private:
    void buildMenu();
    void armWatcherFromDiscovery();
    void refreshStatus(const ScanResult& result);
    void refreshRecentMenu();
    void notifyChanges(const ScanResult& result);
    ScanOptions scanOptions() const;

    QString m_dataDir;
    QString m_screenshotPath;
    QSystemTrayIcon* m_tray = nullptr;
    QMenu* m_menu = nullptr;
    QMenu* m_recentMenu = nullptr;
    QAction* m_statusAction = nullptr;
    QAction* m_rescanAction = nullptr;
    QFutureWatcher<ScanResult>* m_watcher = nullptr;
    QFutureWatcher<StoreTrackingResult>* m_storeWatcher = nullptr;
    CompanionServer* m_companion = nullptr;
    QTimer m_companionRescan;
    ProfileWatcher* m_fsWatcher = nullptr;
    QTimer m_periodic;
    QPointer<MainWindow> m_window;
    bool m_firstScan = true;
    bool m_rescanQueued = false;
    int m_scansSinceFullHash = 0;  // fingerprints are trusted between full integrity sweeps
    bool m_showOnStart = false;
    ScanResult m_lastResult;
};

}  // namespace extwatch
