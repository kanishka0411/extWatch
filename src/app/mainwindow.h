#pragma once

#include <QDateTime>
#include <QMainWindow>
#include <QString>
#include <optional>

#include "core/database.h"
#include "core/scanner.h"

class QLabel;
class QLineEdit;
class QStackedWidget;
class QTreeWidget;
class QTreeWidgetItem;

namespace extwatch {

class ExtensionDetailView;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QString dataDir, QWidget* parent = nullptr);

public slots:
    void showScanResult(const extwatch::ScanResult& result);
    void reloadTree();
    void openEvent(qint64 eventId);
    void openExtension(qint64 extensionRowId);
    void setWatchStatus(const QString& status);
    void openSettings();
    void selectDetailTab(int index);
    void setCompanionStatus(int connections, const QStringList& browsers);
    void showActionResult(const QString& title, const QString& text, bool warning);

signals:
    void rescanRequested();
    void settingsChanged();
    void eventAcknowledged();
    void toggleEnabledRequested(const QString& extId, bool enable);
    void companionSetupRequested();

private:
    void onSelectionChanged();
    void applyFilter(const QString& text);
    void updateStatus();
    void selectExtensionItem(qint64 extensionRowId);

    QString m_dataDir;
    Database m_db;
    QTreeWidget* m_tree = nullptr;
    QLineEdit* m_search = nullptr;
    QStackedWidget* m_stack = nullptr;
    QLabel* m_welcome = nullptr;
    ExtensionDetailView* m_detail = nullptr;
    QLabel* m_status = nullptr;
    QString m_watchStatus;
    QDateTime m_lastScan;
    int m_extensionCount = 0;
    int m_profileCount = 0;
    int m_unacknowledged = 0;
    int m_companionConnections = 0;
    QStringList m_companionBrowsers;
};

}  // namespace extwatch
