#pragma once

#include <QDateTime>
#include <QJsonObject>
#include <QList>
#include <QString>
#include <QStringList>
#include <optional>

#include "core/browserkind.h"
#include "core/discovery.h"
#include "core/hashing.h"
#include "core/rules.h"

namespace extwatch {

struct ScanOptions {
    QList<BrowserInstall> candidates;  // empty: knownBrowserLocations()
    QString dataDir;                   // sqlite + blobs; ignored when persist is false
    bool persist = true;
    bool computeHashes = true;
    bool analyze = true;  // compute signatures and findings for new events
    int settleSeconds = 3;  // a version directory modified more recently than this is still being written
    int settleRetries = 2;  // how many times a scan waits and retries for unsettled directories
    std::optional<BrowserKind> onlyBrowser;
    QString onlyProfile;  // dir name or display name
};

struct VersionReport {
    QString dirName;
    QString version;
    QString path;
    QString treeHash;  // hex, empty when hashing was skipped
    bool active = false;
    bool newlySeen = false;
    bool settled = true;      // false: still being written, not archived this pass
    bool reused = false;      // stat fingerprint matched the archive, hashing skipped
    QString fingerprint;
    bool hasWebstoreMetadata = false;
    bool keyMatchesId = true;
    int fileCount = 0;
    qint64 bytes = 0;
    std::optional<qint64> versionRowId;
    QJsonObject manifest;
    QStringList warnings;
    QList<FileEntry> files;  // not serialized; reused when archiving
};

struct ExtensionReport {
    QString id;
    QString name;
    QString activeVersion;
    int location = 0;
    QString locationId;
    bool enabled = false;
    bool fromWebstore = false;
    bool unpacked = false;
    QString updateUrl;
    QStringList disableReasons;
    QStringList notes;
    std::optional<QDateTime> installTime;
    std::optional<QDateTime> updateTime;
    QList<VersionReport> versions;  // newest first
    std::optional<qint64> extensionRowId;
};

struct ProfileReport {
    Profile profile;
    std::optional<qint64> profileRowId;
    QList<ExtensionReport> extensions;
    QStringList warnings;
};

struct BrowserReport {
    BrowserInstall install;
    std::optional<qint64> browserRowId;
    QList<ProfileReport> profiles;
};

struct ScanEvent {
    QString kind;  // baseline, updated, modified_in_place, pending_version, enabled, disabled, removed
    QString browserKind;
    QString browserName;
    QString profileDir;
    QString profileName;
    QString extId;
    QString extName;
    QString fromVersion;
    QString toVersion;
    std::optional<qint64> eventRowId;
    std::optional<qint64> extensionRowId;
    std::optional<qint64> fromVersionRowId;
    std::optional<qint64> toVersionRowId;
    QString maxSeverity;       // info, low, medium, high; empty when not analyzed
    QString findingsSummary;   // one line, e.g. "+host access <all_urls>, polls x every 5 min"
    QList<Finding> findings;

    QString summary() const;   // "Name updated 1.0 → 1.2: <findings summary>"
    QString headline() const;  // "Name 1.0 → 1.2"
};

struct ScanResult {
    QDateTime scannedAt;
    QList<BrowserReport> browsers;
    QList<ScanEvent> events;
    QStringList warnings;
    QString dataDir;
    bool needsRescan = false;  // an unsettled version directory was skipped

    int profileCount() const;
    int extensionCount() const;
    QJsonObject toJson() const;
};

// Per-user data directory for the database and blob store.
QString defaultDataDir();
QString databasePath(const QString& dataDir);

// Discovers browsers and profiles, inventories extensions, snapshots every version directory
// into the archive and records events. Opens its own database connection (thread-safe to call
// from a worker thread).
ScanResult runScan(const ScanOptions& options);

}  // namespace extwatch
