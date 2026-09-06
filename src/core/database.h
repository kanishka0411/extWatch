#pragma once

#include <QList>
#include <QSqlDatabase>
#include <QString>
#include <optional>

#include "core/hashing.h"
#include "core/storemeta.h"

namespace extwatch {

struct BrowserRow {
    qint64 id = 0;
    QString kind;
    QString userDataDir;
    QString displayName;
    qint64 firstSeen = 0;
    qint64 lastSeen = 0;
};

struct ProfileRow {
    qint64 id = 0;
    qint64 browserId = 0;
    QString dirName;
    QString displayName;
    qint64 firstSeen = 0;
    qint64 lastSeen = 0;
};

struct ExtensionRow {
    qint64 id = 0;
    qint64 profileId = 0;
    QString extId;
    QString name;
    int location = 0;
    bool fromWebstore = false;
    bool enabled = true;
    qint64 firstSeen = 0;
    qint64 lastSeen = 0;
    std::optional<qint64> currentVersionId;
    QString grantsJson;  // effective host/API grants from the browser prefs
};

struct VersionRow {
    qint64 id = 0;
    qint64 extensionId = 0;
    QString version;
    QString dirName;
    QString treeHash;  // hex
    qint64 firstSeen = 0;
    qint64 lastSeen = 0;
    std::optional<qint64> activatedAt;
    QString manifestJson;
    QString signatureJson;
    int fileCount = 0;
    qint64 bytes = 0;
    bool keyMatchesId = true;
    bool hasWebstoreMetadata = false;
    QString statFingerprint;  // directoryFingerprint() when this tree was last seen on disk
    QString state;            // "complete"; snapshots are only recorded once every blob is stored
};

struct QuarantineRow {
    QString id;  // random, also the directory name under <dataDir>/quarantine/
    qint64 extensionId = 0;
    QString extId;
    QString browserKind;
    QString userDataDir;
    QString profileDir;
    QString version;
    QString dirName;
    QString treeHash;
    QString originalPath;
    QString quarantinePath;
    qint64 createdAt = 0;
    QString state;  // quarantined, copied_source_present, restored
};

struct EventRow {
    qint64 id = 0;
    qint64 extensionId = 0;
    QString kind;  // baseline, updated, pending_version, enabled, disabled, removed
    std::optional<qint64> fromVersionId;
    std::optional<qint64> toVersionId;
    qint64 at = 0;
    QString maxSeverity;  // info, low, medium, high (empty when not analyzed)
    QString findingsJson;
    bool acknowledged = false;
};

// SQLite store for snapshots and events. One instance per thread (Qt SQL connections are
// thread-affine); instances are cheap to create.
class Database {
public:
    static constexpr int kSchemaVersion = 2;

    Database();
    ~Database();
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    bool open(const QString& filePath, QString* error = nullptr);
    bool isOpen() const { return m_db.isOpen(); }
    int schemaVersion();
    bool quickCheck(QString* report = nullptr);
    QString filePath() const { return m_filePath; }
    QString lastError() const { return m_lastError; }

    bool transaction();
    bool commit();
    bool rollback();

    qint64 upsertBrowser(const QString& kind, const QString& userDataDir,
                         const QString& displayName, qint64 now);
    qint64 upsertProfile(qint64 browserId, const QString& dirName, const QString& displayName,
                         qint64 now);
    qint64 upsertExtension(qint64 profileId, const QString& extId, const QString& name,
                           int location, bool fromWebstore, bool enabled, qint64 now);
    bool setCurrentVersion(qint64 extensionId, std::optional<qint64> versionId);
    bool setExtensionGrants(qint64 extensionId, const QString& grantsJson);

    std::optional<qint64> findVersionByTreeHash(qint64 extensionId, const QString& treeHashHex);
    qint64 insertVersion(const VersionRow& row);
    bool touchVersion(qint64 versionId, qint64 now, bool activated);
    bool setVersionFingerprint(qint64 versionId, const QString& fingerprint);
    bool setSignature(qint64 versionId, const QString& signatureJson);
    bool insertFiles(qint64 versionId, const QList<FileEntry>& files);
    qint64 insertEvent(const EventRow& row);
    bool setEventFindings(qint64 eventId, const QString& maxSeverity, const QString& findingsJson);
    bool acknowledgeEvent(qint64 eventId, bool acknowledged);

    QList<BrowserRow> browsers();
    QList<ProfileRow> profilesForBrowser(qint64 browserId);
    std::optional<ProfileRow> profileById(qint64 id);
    std::optional<BrowserRow> browserById(qint64 id);
    QList<ExtensionRow> extensionsForProfile(qint64 profileId);
    QList<ExtensionRow> extensionsByExtId(const QString& extId);
    std::optional<ExtensionRow> extensionById(qint64 id);
    std::optional<ExtensionRow> findExtension(qint64 profileId, const QString& extId);
    QList<VersionRow> versionsForExtension(qint64 extensionId);
    std::optional<VersionRow> versionById(qint64 id);
    QList<FileEntry> filesForVersion(qint64 versionId);
    QList<EventRow> eventsForExtension(qint64 extensionId);
    QList<EventRow> recentEvents(int limit, bool unacknowledgedOnly = false);
    std::optional<EventRow> eventById(qint64 id);
    // Events with a target version whose findings were never computed (crash between scan and analysis).
    QList<EventRow> unanalyzedEvents(int limit);
    QList<EventRow> allEvents();

    bool insertQuarantine(const QuarantineRow& row);
    bool setQuarantineState(const QString& id, const QString& state);
    std::optional<QuarantineRow> quarantineById(const QString& id);
    QList<QuarantineRow> quarantinesForExtension(qint64 extensionId);
    QList<QuarantineRow> allQuarantines();
    QList<VersionRow> allVersions();

    bool upsertStoreListing(const StoreListing& listing);
    std::optional<StoreListing> storeListing(const QString& extId);

private:
    bool initSchema(QString* error);
    bool exec(class QSqlQuery& query);

    QSqlDatabase m_db;
    QString m_connectionName;
    QString m_filePath;
    QString m_lastError;
};

}  // namespace extwatch
