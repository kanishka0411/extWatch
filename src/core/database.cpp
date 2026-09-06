#include "core/database.h"

#include <QAtomicInt>
#include <QDir>
#include <QFileInfo>
#include <QJsonDocument>
#include <QSqlError>
#include <QSqlQuery>
#include <QVariant>

namespace extwatch {

namespace {

QAtomicInt g_connectionCounter{0};

const char* const kSchema[] = {
    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)",
    "CREATE TABLE IF NOT EXISTS browsers ("
    " id INTEGER PRIMARY KEY, kind TEXT NOT NULL, user_data_dir TEXT NOT NULL UNIQUE,"
    " display_name TEXT, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS profiles ("
    " id INTEGER PRIMARY KEY, browser_id INTEGER NOT NULL REFERENCES browsers(id),"
    " dir_name TEXT NOT NULL, display_name TEXT, first_seen INTEGER NOT NULL,"
    " last_seen INTEGER NOT NULL, UNIQUE(browser_id, dir_name))",
    "CREATE TABLE IF NOT EXISTS extensions ("
    " id INTEGER PRIMARY KEY, profile_id INTEGER NOT NULL REFERENCES profiles(id),"
    " ext_id TEXT NOT NULL, name TEXT, location INTEGER, from_webstore INTEGER,"
    " enabled INTEGER, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,"
    " current_version_id INTEGER, UNIQUE(profile_id, ext_id))",
    "CREATE TABLE IF NOT EXISTS versions ("
    " id INTEGER PRIMARY KEY, extension_id INTEGER NOT NULL REFERENCES extensions(id),"
    " version TEXT NOT NULL, dir_name TEXT NOT NULL, tree_hash TEXT NOT NULL,"
    " first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, activated_at INTEGER,"
    " manifest_json TEXT, signature_json TEXT, file_count INTEGER, bytes INTEGER,"
    " key_matches_id INTEGER, has_webstore_metadata INTEGER,"
    " UNIQUE(extension_id, tree_hash))",
    "CREATE TABLE IF NOT EXISTS files ("
    " version_id INTEGER NOT NULL REFERENCES versions(id), path TEXT NOT NULL,"
    " sha256 TEXT NOT NULL, size INTEGER NOT NULL, PRIMARY KEY(version_id, path))",
    "CREATE TABLE IF NOT EXISTS events ("
    " id INTEGER PRIMARY KEY, extension_id INTEGER NOT NULL REFERENCES extensions(id),"
    " kind TEXT NOT NULL, from_version_id INTEGER, to_version_id INTEGER,"
    " at INTEGER NOT NULL, max_severity TEXT, findings_json TEXT,"
    " acknowledged INTEGER NOT NULL DEFAULT 0)",
    "CREATE TABLE IF NOT EXISTS store_listings ("
    " ext_id TEXT PRIMARY KEY, fetched_at INTEGER NOT NULL, found INTEGER NOT NULL,"
    " developer TEXT, developer_email TEXT, version TEXT, json TEXT)",
    "CREATE INDEX IF NOT EXISTS idx_events_ext ON events(extension_id, at)",
    "CREATE INDEX IF NOT EXISTS idx_versions_ext ON versions(extension_id)",
    "CREATE INDEX IF NOT EXISTS idx_extensions_extid ON extensions(ext_id)",
    "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', '1')",
};

// Migrations are applied in order inside a transaction; index i upgrades version i+1 to i+2.
const QList<QStringList> kMigrations = {
    // 1 -> 2: snapshot fingerprints and states, effective grants, quarantine records
    {
        QStringLiteral("ALTER TABLE versions ADD COLUMN stat_fingerprint TEXT"),
        QStringLiteral("ALTER TABLE versions ADD COLUMN state TEXT NOT NULL DEFAULT 'complete'"),
        QStringLiteral("ALTER TABLE extensions ADD COLUMN grants_json TEXT"),
        QStringLiteral("CREATE TABLE IF NOT EXISTS quarantines ("
                       " id TEXT PRIMARY KEY, extension_id INTEGER NOT NULL REFERENCES extensions(id),"
                       " ext_id TEXT NOT NULL, browser_kind TEXT, user_data_dir TEXT, profile_dir TEXT,"
                       " version TEXT, dir_name TEXT, tree_hash TEXT, original_path TEXT NOT NULL,"
                       " quarantine_path TEXT NOT NULL, created_at INTEGER NOT NULL, state TEXT NOT NULL)"),
    },
    // 2 -> 3: presence is state, not the last event; findings carry their rules generation
    {
        QStringLiteral("ALTER TABLE extensions ADD COLUMN present INTEGER NOT NULL DEFAULT 1"),
        QStringLiteral("ALTER TABLE events ADD COLUMN findings_schema INTEGER NOT NULL DEFAULT 0"),
        QStringLiteral("UPDATE extensions SET present = 0 WHERE id IN (SELECT e.extension_id FROM events e"
                       " WHERE e.kind = 'removed' AND e.id = (SELECT MAX(id) FROM events WHERE extension_id = e.extension_id))"),
    },
};

std::optional<qint64> optionalInt(const QVariant& v) {
    if (v.isNull() || !v.isValid()) {
        return std::nullopt;
    }
    return v.toLongLong();
}

QVariant fromOptional(const std::optional<qint64>& v) {
    return v ? QVariant(*v) : QVariant(QMetaType(QMetaType::LongLong));
}

BrowserRow readBrowser(const QSqlQuery& q) {
    BrowserRow r;
    r.id = q.value(0).toLongLong();
    r.kind = q.value(1).toString();
    r.userDataDir = q.value(2).toString();
    r.displayName = q.value(3).toString();
    r.firstSeen = q.value(4).toLongLong();
    r.lastSeen = q.value(5).toLongLong();
    return r;
}

ProfileRow readProfile(const QSqlQuery& q) {
    ProfileRow r;
    r.id = q.value(0).toLongLong();
    r.browserId = q.value(1).toLongLong();
    r.dirName = q.value(2).toString();
    r.displayName = q.value(3).toString();
    r.firstSeen = q.value(4).toLongLong();
    r.lastSeen = q.value(5).toLongLong();
    return r;
}

ExtensionRow readExtension(const QSqlQuery& q) {
    ExtensionRow r;
    r.id = q.value(0).toLongLong();
    r.profileId = q.value(1).toLongLong();
    r.extId = q.value(2).toString();
    r.name = q.value(3).toString();
    r.location = q.value(4).toInt();
    r.fromWebstore = q.value(5).toBool();
    r.enabled = q.value(6).toBool();
    r.firstSeen = q.value(7).toLongLong();
    r.lastSeen = q.value(8).toLongLong();
    r.currentVersionId = optionalInt(q.value(9));
    r.grantsJson = q.value(10).toString();
    r.present = q.value(11).toBool();
    return r;
}

QuarantineRow readQuarantine(const QSqlQuery& q) {
    QuarantineRow r;
    r.id = q.value(0).toString();
    r.extensionId = q.value(1).toLongLong();
    r.extId = q.value(2).toString();
    r.browserKind = q.value(3).toString();
    r.userDataDir = q.value(4).toString();
    r.profileDir = q.value(5).toString();
    r.version = q.value(6).toString();
    r.dirName = q.value(7).toString();
    r.treeHash = q.value(8).toString();
    r.originalPath = q.value(9).toString();
    r.quarantinePath = q.value(10).toString();
    r.createdAt = q.value(11).toLongLong();
    r.state = q.value(12).toString();
    return r;
}

VersionRow readVersion(const QSqlQuery& q) {
    VersionRow r;
    r.id = q.value(0).toLongLong();
    r.extensionId = q.value(1).toLongLong();
    r.version = q.value(2).toString();
    r.dirName = q.value(3).toString();
    r.treeHash = q.value(4).toString();
    r.firstSeen = q.value(5).toLongLong();
    r.lastSeen = q.value(6).toLongLong();
    r.activatedAt = optionalInt(q.value(7));
    r.manifestJson = q.value(8).toString();
    r.signatureJson = q.value(9).toString();
    r.fileCount = q.value(10).toInt();
    r.bytes = q.value(11).toLongLong();
    r.keyMatchesId = q.value(12).toBool();
    r.hasWebstoreMetadata = q.value(13).toBool();
    r.statFingerprint = q.value(14).toString();
    r.state = q.value(15).toString();
    return r;
}

EventRow readEvent(const QSqlQuery& q) {
    EventRow r;
    r.id = q.value(0).toLongLong();
    r.extensionId = q.value(1).toLongLong();
    r.kind = q.value(2).toString();
    r.fromVersionId = optionalInt(q.value(3));
    r.toVersionId = optionalInt(q.value(4));
    r.at = q.value(5).toLongLong();
    r.maxSeverity = q.value(6).toString();
    r.findingsJson = q.value(7).toString();
    r.acknowledged = q.value(8).toBool();
    r.findingsSchema = q.value(9).toInt();
    return r;
}

const char* const kBrowserCols = "id, kind, user_data_dir, display_name, first_seen, last_seen";
const char* const kProfileCols = "id, browser_id, dir_name, display_name, first_seen, last_seen";
const char* const kExtensionCols =
    "id, profile_id, ext_id, name, location, from_webstore, enabled, first_seen, last_seen,"
    " current_version_id, grants_json, present";
const char* const kVersionCols =
    "id, extension_id, version, dir_name, tree_hash, first_seen, last_seen, activated_at,"
    " manifest_json, signature_json, file_count, bytes, key_matches_id, has_webstore_metadata,"
    " stat_fingerprint, state";
const char* const kQuarantineCols =
    "id, extension_id, ext_id, browser_kind, user_data_dir, profile_dir, version, dir_name, tree_hash,"
    " original_path, quarantine_path, created_at, state";
const char* const kEventCols =
    "id, extension_id, kind, from_version_id, to_version_id, at, max_severity, findings_json,"
    " acknowledged, findings_schema";

}  // namespace

Database::Database()
    : m_connectionName(QStringLiteral("extwatch_%1").arg(g_connectionCounter.fetchAndAddRelaxed(1))) {}

Database::~Database() {
    if (m_db.isValid()) {
        m_db.close();
        m_db = QSqlDatabase();
        QSqlDatabase::removeDatabase(m_connectionName);
    }
}

bool Database::exec(QSqlQuery& query) {
    if (!query.exec()) {
        m_lastError = query.lastError().text();
        return false;
    }
    return true;
}

bool Database::open(const QString& filePath, QString* error) {
    if (!QDir().mkpath(QFileInfo(filePath).path())) {
        m_lastError = QStringLiteral("cannot create %1").arg(QFileInfo(filePath).path());
        if (error) {
            *error = m_lastError;
        }
        return false;
    }
    m_db = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), m_connectionName);
    m_db.setDatabaseName(filePath);
    m_filePath = filePath;
    if (!m_db.open()) {
        m_lastError = m_db.lastError().text();
        if (error) {
            *error = m_lastError;
        }
        return false;
    }
    QSqlQuery pragma(m_db);
    pragma.exec(QStringLiteral("PRAGMA journal_mode=WAL"));
    pragma.exec(QStringLiteral("PRAGMA synchronous=NORMAL"));
    pragma.exec(QStringLiteral("PRAGMA foreign_keys=ON"));
    pragma.exec(QStringLiteral("PRAGMA busy_timeout=5000"));
    return initSchema(error);
}

int Database::schemaVersion() {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT value FROM meta WHERE key = 'schema_version'"));
    if (exec(q) && q.next()) {
        return q.value(0).toInt();
    }
    return 0;
}

bool Database::quickCheck(QString* report) {
    QSqlQuery q(m_db);
    if (!q.exec(QStringLiteral("PRAGMA quick_check")) || !q.next()) {
        m_lastError = q.lastError().text();
        if (report) *report = m_lastError;
        return false;
    }
    const QString result = q.value(0).toString();
    if (report) *report = result;
    return result == QStringLiteral("ok");
}

bool Database::initSchema(QString* error) {
    for (const char* stmt : kSchema) {
        QSqlQuery q(m_db);
        if (!q.exec(QString::fromLatin1(stmt))) {
            m_lastError = q.lastError().text();
            if (error) {
                *error = m_lastError;
            }
            return false;
        }
    }
    int version = schemaVersion();
    if (version > kSchemaVersion) {
        m_lastError = QStringLiteral("database schema %1 is newer than this ExtWatch understands (%2)")
                          .arg(version).arg(kSchemaVersion);
        if (error) {
            *error = m_lastError;
        }
        return false;
    }
    while (version < kSchemaVersion) {
        const QStringList& steps = kMigrations.at(version - 1);
        if (!m_db.transaction()) {
            m_lastError = m_db.lastError().text();
            if (error) *error = m_lastError;
            return false;
        }
        for (const QString& stmt : steps) {
            QSqlQuery q(m_db);
            if (!q.exec(stmt)) {
                m_lastError = QStringLiteral("migration to schema %1 failed: %2").arg(version + 1).arg(q.lastError().text());
                m_db.rollback();
                if (error) *error = m_lastError;
                return false;
            }
        }
        QSqlQuery set(m_db);
        set.prepare(QStringLiteral("UPDATE meta SET value = ? WHERE key = 'schema_version'"));
        set.addBindValue(QString::number(version + 1));
        if (!exec(set) || !m_db.commit()) {
            m_db.rollback();
            if (error) *error = m_lastError;
            return false;
        }
        version++;
    }
    return true;
}

bool Database::transaction() { return m_db.transaction(); }
bool Database::commit() { return m_db.commit(); }
bool Database::rollback() { return m_db.rollback(); }

qint64 Database::upsertBrowser(const QString& kind, const QString& userDataDir,
                               const QString& displayName, qint64 now) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral(
        "INSERT INTO browsers(kind, user_data_dir, display_name, first_seen, last_seen)"
        " VALUES(?, ?, ?, ?, ?) ON CONFLICT(user_data_dir) DO UPDATE SET"
        " display_name = excluded.display_name, last_seen = excluded.last_seen"));
    q.addBindValue(kind);
    q.addBindValue(userDataDir);
    q.addBindValue(displayName);
    q.addBindValue(now);
    q.addBindValue(now);
    if (!exec(q)) {
        return -1;
    }
    QSqlQuery sel(m_db);
    sel.prepare(QStringLiteral("SELECT id FROM browsers WHERE user_data_dir = ?"));
    sel.addBindValue(userDataDir);
    return exec(sel) && sel.next() ? sel.value(0).toLongLong() : -1;
}

qint64 Database::upsertProfile(qint64 browserId, const QString& dirName,
                               const QString& displayName, qint64 now) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral(
        "INSERT INTO profiles(browser_id, dir_name, display_name, first_seen, last_seen)"
        " VALUES(?, ?, ?, ?, ?) ON CONFLICT(browser_id, dir_name) DO UPDATE SET"
        " display_name = excluded.display_name, last_seen = excluded.last_seen"));
    q.addBindValue(browserId);
    q.addBindValue(dirName);
    q.addBindValue(displayName);
    q.addBindValue(now);
    q.addBindValue(now);
    if (!exec(q)) {
        return -1;
    }
    QSqlQuery sel(m_db);
    sel.prepare(QStringLiteral("SELECT id FROM profiles WHERE browser_id = ? AND dir_name = ?"));
    sel.addBindValue(browserId);
    sel.addBindValue(dirName);
    return exec(sel) && sel.next() ? sel.value(0).toLongLong() : -1;
}

qint64 Database::upsertExtension(qint64 profileId, const QString& extId, const QString& name,
                                 int location, bool fromWebstore, bool enabled, qint64 now) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral(
        "INSERT INTO extensions(profile_id, ext_id, name, location, from_webstore, enabled,"
        " first_seen, last_seen) VALUES(?, ?, ?, ?, ?, ?, ?, ?)"
        " ON CONFLICT(profile_id, ext_id) DO UPDATE SET name = excluded.name,"
        " location = excluded.location, from_webstore = excluded.from_webstore,"
        " enabled = excluded.enabled, last_seen = excluded.last_seen, present = 1"));
    q.addBindValue(profileId);
    q.addBindValue(extId);
    q.addBindValue(name);
    q.addBindValue(location);
    q.addBindValue(fromWebstore ? 1 : 0);
    q.addBindValue(enabled ? 1 : 0);
    q.addBindValue(now);
    q.addBindValue(now);
    if (!exec(q)) {
        return -1;
    }
    const std::optional<ExtensionRow> row = findExtension(profileId, extId);
    return row ? row->id : -1;
}

bool Database::setCurrentVersion(qint64 extensionId, std::optional<qint64> versionId) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("UPDATE extensions SET current_version_id = ? WHERE id = ?"));
    q.addBindValue(fromOptional(versionId));
    q.addBindValue(extensionId);
    return exec(q);
}

std::optional<qint64> Database::findVersionByTreeHash(qint64 extensionId,
                                                      const QString& treeHashHex) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT id FROM versions WHERE extension_id = ? AND tree_hash = ?"));
    q.addBindValue(extensionId);
    q.addBindValue(treeHashHex);
    if (exec(q) && q.next()) {
        return q.value(0).toLongLong();
    }
    return std::nullopt;
}

qint64 Database::insertVersion(const VersionRow& r) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral(
        "INSERT INTO versions(extension_id, version, dir_name, tree_hash, first_seen, last_seen,"
        " activated_at, manifest_json, signature_json, file_count, bytes, key_matches_id,"
        " has_webstore_metadata, stat_fingerprint, state) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"));
    q.addBindValue(r.extensionId);
    q.addBindValue(r.version);
    q.addBindValue(r.dirName);
    q.addBindValue(r.treeHash);
    q.addBindValue(r.firstSeen);
    q.addBindValue(r.lastSeen);
    q.addBindValue(fromOptional(r.activatedAt));
    q.addBindValue(r.manifestJson);
    q.addBindValue(r.signatureJson);
    q.addBindValue(r.fileCount);
    q.addBindValue(r.bytes);
    q.addBindValue(r.keyMatchesId ? 1 : 0);
    q.addBindValue(r.hasWebstoreMetadata ? 1 : 0);
    q.addBindValue(r.statFingerprint);
    q.addBindValue(r.state.isEmpty() ? QStringLiteral("complete") : r.state);
    return exec(q) ? q.lastInsertId().toLongLong() : -1;
}

bool Database::setVersionFingerprint(qint64 versionId, const QString& fingerprint) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("UPDATE versions SET stat_fingerprint = ? WHERE id = ?"));
    q.addBindValue(fingerprint);
    q.addBindValue(versionId);
    return exec(q);
}

bool Database::setExtensionGrants(qint64 extensionId, const QString& grantsJson) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("UPDATE extensions SET grants_json = ? WHERE id = ?"));
    q.addBindValue(grantsJson);
    q.addBindValue(extensionId);
    return exec(q);
}

bool Database::touchVersion(qint64 versionId, qint64 now, bool activated) {
    QSqlQuery q(m_db);
    if (activated) {
        q.prepare(QStringLiteral("UPDATE versions SET last_seen = ?, activated_at ="
                                 " COALESCE(activated_at, ?) WHERE id = ?"));
        q.addBindValue(now);
        q.addBindValue(now);
    } else {
        q.prepare(QStringLiteral("UPDATE versions SET last_seen = ? WHERE id = ?"));
        q.addBindValue(now);
    }
    q.addBindValue(versionId);
    return exec(q);
}

bool Database::setSignature(qint64 versionId, const QString& signatureJson) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("UPDATE versions SET signature_json = ? WHERE id = ?"));
    q.addBindValue(signatureJson);
    q.addBindValue(versionId);
    return exec(q);
}

bool Database::insertFiles(qint64 versionId, const QList<FileEntry>& files) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral(
        "INSERT OR REPLACE INTO files(version_id, path, sha256, size) VALUES(?, ?, ?, ?)"));
    for (const FileEntry& f : files) {
        q.addBindValue(versionId);
        q.addBindValue(f.relPath);
        q.addBindValue(toHex(f.sha256));
        q.addBindValue(f.size);
        if (!exec(q)) {
            return false;
        }
    }
    return true;
}

qint64 Database::insertEvent(const EventRow& r) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral(
        "INSERT INTO events(extension_id, kind, from_version_id, to_version_id, at, max_severity,"
        " findings_json, acknowledged, findings_schema) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)"));
    q.addBindValue(r.extensionId);
    q.addBindValue(r.kind);
    q.addBindValue(fromOptional(r.fromVersionId));
    q.addBindValue(fromOptional(r.toVersionId));
    q.addBindValue(r.at);
    q.addBindValue(r.maxSeverity);
    q.addBindValue(r.findingsJson);
    q.addBindValue(r.acknowledged ? 1 : 0);
    q.addBindValue(r.findingsSchema);
    return exec(q) ? q.lastInsertId().toLongLong() : -1;
}

bool Database::setEventFindings(qint64 eventId, const QString& maxSeverity,
                                const QString& findingsJson, int findingsSchema) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("UPDATE events SET max_severity = ?, findings_json = ?, findings_schema = ? WHERE id = ?"));
    q.addBindValue(maxSeverity);
    q.addBindValue(findingsJson);
    q.addBindValue(findingsSchema);
    q.addBindValue(eventId);
    return exec(q);
}

bool Database::setExtensionPresent(qint64 extensionId, bool present) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("UPDATE extensions SET present = ? WHERE id = ?"));
    q.addBindValue(present ? 1 : 0);
    q.addBindValue(extensionId);
    return exec(q);
}

QString Database::metaValue(const QString& key) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT value FROM meta WHERE key = ?"));
    q.addBindValue(key);
    if (exec(q) && q.next()) {
        return q.value(0).toString();
    }
    return {};
}

bool Database::setMetaValue(const QString& key, const QString& value) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"));
    q.addBindValue(key);
    q.addBindValue(value);
    return exec(q);
}

bool Database::acknowledgeEvent(qint64 eventId, bool acknowledged) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("UPDATE events SET acknowledged = ? WHERE id = ?"));
    q.addBindValue(acknowledged ? 1 : 0);
    q.addBindValue(eventId);
    return exec(q);
}

QList<BrowserRow> Database::browsers() {
    QList<BrowserRow> out;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT %1 FROM browsers ORDER BY kind, user_data_dir")
                  .arg(QLatin1StringView(kBrowserCols)));
    if (exec(q)) {
        while (q.next()) {
            out.append(readBrowser(q));
        }
    }
    return out;
}

std::optional<BrowserRow> Database::browserById(qint64 id) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT %1 FROM browsers WHERE id = ?")
                  .arg(QLatin1StringView(kBrowserCols)));
    q.addBindValue(id);
    if (exec(q) && q.next()) {
        return readBrowser(q);
    }
    return std::nullopt;
}

QList<ProfileRow> Database::profilesForBrowser(qint64 browserId) {
    QList<ProfileRow> out;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT %1 FROM profiles WHERE browser_id = ? ORDER BY dir_name")
                  .arg(QLatin1StringView(kProfileCols)));
    q.addBindValue(browserId);
    if (exec(q)) {
        while (q.next()) {
            out.append(readProfile(q));
        }
    }
    return out;
}

std::optional<ProfileRow> Database::profileById(qint64 id) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT %1 FROM profiles WHERE id = ?")
                  .arg(QLatin1StringView(kProfileCols)));
    q.addBindValue(id);
    if (exec(q) && q.next()) {
        return readProfile(q);
    }
    return std::nullopt;
}

QList<ExtensionRow> Database::extensionsForProfile(qint64 profileId, bool presentOnly) {
    QList<ExtensionRow> out;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT %1 FROM extensions WHERE profile_id = ?%2 ORDER BY name")
                  .arg(QLatin1StringView(kExtensionCols), presentOnly ? QStringLiteral(" AND present = 1") : QString()));
    q.addBindValue(profileId);
    if (exec(q)) {
        while (q.next()) {
            out.append(readExtension(q));
        }
    }
    return out;
}

QList<ExtensionRow> Database::extensionsByExtId(const QString& extId) {
    QList<ExtensionRow> out;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT %1 FROM extensions WHERE ext_id = ? ORDER BY profile_id")
                  .arg(QLatin1StringView(kExtensionCols)));
    q.addBindValue(extId);
    if (exec(q)) {
        while (q.next()) {
            out.append(readExtension(q));
        }
    }
    return out;
}

std::optional<ExtensionRow> Database::extensionById(qint64 id) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT %1 FROM extensions WHERE id = ?")
                  .arg(QLatin1StringView(kExtensionCols)));
    q.addBindValue(id);
    if (exec(q) && q.next()) {
        return readExtension(q);
    }
    return std::nullopt;
}

std::optional<ExtensionRow> Database::findExtension(qint64 profileId, const QString& extId) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT %1 FROM extensions WHERE profile_id = ? AND ext_id = ?")
                  .arg(QLatin1StringView(kExtensionCols)));
    q.addBindValue(profileId);
    q.addBindValue(extId);
    if (exec(q) && q.next()) {
        return readExtension(q);
    }
    return std::nullopt;
}

QList<VersionRow> Database::versionsForExtension(qint64 extensionId) {
    QList<VersionRow> out;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT %1 FROM versions WHERE extension_id = ? ORDER BY first_seen, id")
                  .arg(QLatin1StringView(kVersionCols)));
    q.addBindValue(extensionId);
    if (exec(q)) {
        while (q.next()) {
            out.append(readVersion(q));
        }
    }
    return out;
}

std::optional<VersionRow> Database::versionById(qint64 id) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT %1 FROM versions WHERE id = ?")
                  .arg(QLatin1StringView(kVersionCols)));
    q.addBindValue(id);
    if (exec(q) && q.next()) {
        return readVersion(q);
    }
    return std::nullopt;
}

QList<FileEntry> Database::filesForVersion(qint64 versionId) {
    QList<FileEntry> out;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT path, sha256, size FROM files WHERE version_id = ? ORDER BY path"));
    q.addBindValue(versionId);
    if (exec(q)) {
        while (q.next()) {
            out.append({q.value(0).toString(), QByteArray::fromHex(q.value(1).toByteArray()),
                        q.value(2).toLongLong()});
        }
    }
    return out;
}

QList<EventRow> Database::eventsForExtension(qint64 extensionId) {
    QList<EventRow> out;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT %1 FROM events WHERE extension_id = ? ORDER BY at, id")
                  .arg(QLatin1StringView(kEventCols)));
    q.addBindValue(extensionId);
    if (exec(q)) {
        while (q.next()) {
            out.append(readEvent(q));
        }
    }
    return out;
}

QList<EventRow> Database::recentEvents(int limit, bool unacknowledgedOnly) {
    QList<EventRow> out;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT %1 FROM events %2 ORDER BY at DESC, id DESC LIMIT ?")
                  .arg(QLatin1StringView(kEventCols),
                       unacknowledgedOnly ? QStringLiteral("WHERE acknowledged = 0") : QString()));
    q.addBindValue(limit);
    if (exec(q)) {
        while (q.next()) {
            out.append(readEvent(q));
        }
    }
    return out;
}

bool Database::upsertStoreListing(const StoreListing& listing) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral(
        "INSERT INTO store_listings(ext_id, fetched_at, found, developer, developer_email, version, json)"
        " VALUES(?, ?, ?, ?, ?, ?, ?) ON CONFLICT(ext_id) DO UPDATE SET fetched_at = excluded.fetched_at,"
        " found = excluded.found, developer = excluded.developer, developer_email = excluded.developer_email,"
        " version = excluded.version, json = excluded.json"));
    q.addBindValue(listing.extId);
    q.addBindValue(listing.fetchedAt);
    q.addBindValue(listing.found ? 1 : 0);
    q.addBindValue(listing.developer);
    q.addBindValue(listing.developerEmail);
    q.addBindValue(listing.version);
    q.addBindValue(QString::fromUtf8(QJsonDocument(listing.toJson()).toJson(QJsonDocument::Compact)));
    return exec(q);
}

std::optional<StoreListing> Database::storeListing(const QString& extId) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT json FROM store_listings WHERE ext_id = ?"));
    q.addBindValue(extId);
    if (exec(q) && q.next()) {
        StoreListing l = StoreListing::fromJson(QJsonDocument::fromJson(q.value(0).toString().toUtf8()).object());
        l.extId = extId;
        return l;
    }
    return std::nullopt;
}

std::optional<EventRow> Database::eventById(qint64 id) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT %1 FROM events WHERE id = ?").arg(QLatin1StringView(kEventCols)));
    q.addBindValue(id);
    if (exec(q) && q.next()) {
        return readEvent(q);
    }
    return std::nullopt;
}

QList<EventRow> Database::unanalyzedEvents(int limit) {
    QList<EventRow> out;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT %1 FROM events WHERE to_version_id IS NOT NULL AND"
                             " (max_severity IS NULL OR max_severity = '') AND"
                             " kind IN ('baseline', 'updated', 'pending_version', 'modified_in_place', 'reinstalled')"
                             " ORDER BY id LIMIT ?").arg(QLatin1StringView(kEventCols)));
    q.addBindValue(limit);
    if (exec(q)) {
        while (q.next()) {
            out.append(readEvent(q));
        }
    }
    return out;
}

QList<EventRow> Database::staleFindingsEvents(int findingsSchema, int limit) {
    QList<EventRow> out;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT %1 FROM events WHERE to_version_id IS NOT NULL AND"
                             " max_severity IS NOT NULL AND max_severity <> '' AND findings_schema <> ? AND"
                             " kind IN ('baseline', 'updated', 'pending_version', 'modified_in_place', 'reinstalled')"
                             " ORDER BY id DESC LIMIT ?").arg(QLatin1StringView(kEventCols)));
    q.addBindValue(findingsSchema);
    q.addBindValue(limit);
    if (exec(q)) {
        while (q.next()) {
            out.append(readEvent(q));
        }
    }
    return out;
}

QList<EventRow> Database::allEvents() {
    QList<EventRow> out;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT %1 FROM events ORDER BY id").arg(QLatin1StringView(kEventCols)));
    if (exec(q)) {
        while (q.next()) {
            out.append(readEvent(q));
        }
    }
    return out;
}

QList<VersionRow> Database::allVersions() {
    QList<VersionRow> out;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT %1 FROM versions ORDER BY id").arg(QLatin1StringView(kVersionCols)));
    if (exec(q)) {
        while (q.next()) {
            out.append(readVersion(q));
        }
    }
    return out;
}

bool Database::insertQuarantine(const QuarantineRow& r) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral(
        "INSERT INTO quarantines(id, extension_id, ext_id, browser_kind, user_data_dir, profile_dir, version,"
        " dir_name, tree_hash, original_path, quarantine_path, created_at, state)"
        " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"));
    q.addBindValue(r.id);
    q.addBindValue(r.extensionId);
    q.addBindValue(r.extId);
    q.addBindValue(r.browserKind);
    q.addBindValue(r.userDataDir);
    q.addBindValue(r.profileDir);
    q.addBindValue(r.version);
    q.addBindValue(r.dirName);
    q.addBindValue(r.treeHash);
    q.addBindValue(r.originalPath);
    q.addBindValue(r.quarantinePath);
    q.addBindValue(r.createdAt);
    q.addBindValue(r.state);
    return exec(q);
}

bool Database::setQuarantineState(const QString& id, const QString& state) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("UPDATE quarantines SET state = ? WHERE id = ?"));
    q.addBindValue(state);
    q.addBindValue(id);
    return exec(q);
}

std::optional<QuarantineRow> Database::quarantineById(const QString& id) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT %1 FROM quarantines WHERE id = ?").arg(QLatin1StringView(kQuarantineCols)));
    q.addBindValue(id);
    if (exec(q) && q.next()) {
        return readQuarantine(q);
    }
    return std::nullopt;
}

QList<QuarantineRow> Database::quarantinesForExtension(qint64 extensionId) {
    QList<QuarantineRow> out;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT %1 FROM quarantines WHERE extension_id = ? ORDER BY created_at")
                  .arg(QLatin1StringView(kQuarantineCols)));
    q.addBindValue(extensionId);
    if (exec(q)) {
        while (q.next()) {
            out.append(readQuarantine(q));
        }
    }
    return out;
}

QList<QuarantineRow> Database::allQuarantines() {
    QList<QuarantineRow> out;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT %1 FROM quarantines ORDER BY created_at").arg(QLatin1StringView(kQuarantineCols)));
    if (exec(q)) {
        while (q.next()) {
            out.append(readQuarantine(q));
        }
    }
    return out;
}

std::optional<VersionRow> resolveVersionRef(Database& db, qint64 extensionRowId, const QString& ref, QString* note) {
    const QString version = ref.section(u'@', 0, 0);
    const QString hashPrefix = ref.contains(u'@') ? ref.section(u'@', 1).toLower() : QString();
    std::optional<VersionRow> found;
    int matches = 0;
    for (const VersionRow& v : db.versionsForExtension(extensionRowId)) {
        if (!version.isEmpty() && v.version != version) continue;
        if (!hashPrefix.isEmpty() && !v.treeHash.startsWith(hashPrefix)) continue;
        matches++;
        found = v;  // versionsForExtension is ordered oldest first: keep the newest
    }
    if (matches > 1 && !hashPrefix.isEmpty()) {
        // A short prefix that matches several snapshots is ambiguous; refuse rather than pick one.
        if (note) {
            *note = QStringLiteral("hash prefix %1 matches %2 snapshots of version %3; give more characters")
                        .arg(hashPrefix).arg(matches).arg(version.isEmpty() ? QStringLiteral("(any)") : version);
        }
        return std::nullopt;
    }
    if (matches > 1 && hashPrefix.isEmpty() && note) {
        *note = QStringLiteral("%1 snapshots carry version %2; using the newest (%3). Address one with %2@<tree hash>.")
                    .arg(matches).arg(version, found->treeHash.left(12));
    }
    return found;
}

}  // namespace extwatch
