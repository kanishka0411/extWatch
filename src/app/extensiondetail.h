#pragma once

#include <QWidget>
#include <optional>

#include "core/analyzer.h"
#include "core/blobstore.h"
#include "core/database.h"

class QCheckBox;
class QLabel;
class QListWidget;
class QPushButton;
class QTabWidget;
class QTableWidget;
class QTreeWidget;
class QTreeWidgetItem;

namespace extwatch {

class DiffView;

// Right-hand pane: everything about one installed extension - header and actions, the change
// timeline with findings, manifest and code diffs, archived versions and the behavior signature.
class ExtensionDetailView : public QWidget {
    Q_OBJECT
public:
    explicit ExtensionDetailView(QString dataDir, QWidget* parent = nullptr);

    void showExtension(qint64 extensionRowId, std::optional<qint64> eventId = std::nullopt);
    void refresh();
    qint64 extensionRowId() const { return m_extensionId; }
    void setCurrentTab(int index);

    void setCompanionConnected(bool connected);

signals:
    void inventoryChanged();    // quarantine or restore happened
    void eventAcknowledged();
    void toggleEnabledRequested(const QString& extId, bool enable);
    void companionSetupRequested();

private:
    void buildUi();
    void loadHeader();
    void loadEvents();
    void selectEvent(qint64 eventId);
    void loadVersions();
    void showReport(const ChangeReport& report);
    void populateFiles();
    void showFile(const QString& path);
    void jumpToFinding(QTreeWidgetItem* item);
    void loadSignature(const Signature& sig);

    void openWebStore();
    void copyExtensionsUrl();
    void openFolder();
    void exportVersion();
    void exportReport();
    void quarantine();
    void restoreFromQuarantine();

    QString extensionsDir() const;
    QString versionDirPath(const VersionRow& v) const;
    std::optional<VersionRow> currentVersion();
    QPixmap loadIcon(const VersionRow& v, const QString& iconPath);

    QString m_dataDir;
    Database m_db;
    BlobStore m_blobs;
    qint64 m_extensionId = -1;
    std::optional<ExtensionRow> m_ext;
    std::optional<ProfileRow> m_profile;
    std::optional<BrowserRow> m_browser;
    std::optional<ChangeReport> m_report;
    std::optional<qint64> m_eventId;

    QLabel* m_icon = nullptr;
    QLabel* m_name = nullptr;
    QLabel* m_meta = nullptr;
    QLabel* m_idLabel = nullptr;
    QLabel* m_badge = nullptr;
    QPushButton* m_quarantineBtn = nullptr;
    QPushButton* m_restoreBtn = nullptr;
    QPushButton* m_folderBtn = nullptr;
    QPushButton* m_toggleBtn = nullptr;
    QPushButton* m_setupBtn = nullptr;
    bool m_companionConnected = false;

    QTabWidget* m_tabs = nullptr;
    QTreeWidget* m_events = nullptr;
    QLabel* m_findingsTitle = nullptr;
    QTreeWidget* m_findings = nullptr;
    QLabel* m_findingDetail = nullptr;
    QPushButton* m_exportReportBtn = nullptr;
    DiffView* m_manifestDiff = nullptr;
    QListWidget* m_files = nullptr;
    QCheckBox* m_changedOnly = nullptr;
    DiffView* m_codeDiff = nullptr;
    QTableWidget* m_versions = nullptr;
    QTreeWidget* m_signature = nullptr;
};

}  // namespace extwatch
