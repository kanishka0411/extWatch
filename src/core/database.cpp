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
    return r;
}

const char* const kBrowserCols = "id, kind, user_data_dir, display_name, first_seen, last_seen";
const char* const kProfileCols = "id, browser_id, dir_name, display_name, first_seen, last_seen";
const char* const kExtensionCols =
    "id, profile_id, ext_id, name, location, from_webstore, enabled, first_seen, last_seen,"
    " current_version_id";
const char* const kVersionCols =
    "id, extension_id, version, dir_name, tree_hash, first_seen, last_seen, activated_at,"
    " manifest_json, signature_json, file_count, bytes, key_matches_id, has_webstore_metadata";
const char* const kEventCols =
    "id, extension_id, kind, from_version_id, to_version_id, at, max_severity, findings_json,"
    " acknowledged";

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
        " enabled = excluded.enabled, last_seen = excluded.last_seen"));
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
        " has_webstore_metadata) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"));
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
    return exec(q) ? q.lastInsertId().toLongLong() : -1;
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
        " findings_json, acknowledged) VALUES(?, ?, ?, ?, ?, ?, ?, ?)"));
    q.addBindValue(r.extensionId);
    q.addBindValue(r.kind);
    q.addBindValue(fromOptional(r.fromVersionId));
    q.addBindValue(fromOptional(r.toVersionId));
    q.addBindValue(r.at);
    q.addBindValue(r.maxSeverity);
    q.addBindValue(r.findingsJson);
    q.addBindValue(r.acknowledged ? 1 : 0);
    return exec(q) ? q.lastInsertId().toLongLong() : -1;
}

bool Database::setEventFindings(qint64 eventId, const QString& maxSeverity,
                                const QString& findingsJson) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("UPDATE events SET max_severity = ?, findings_json = ? WHERE id = ?"));
    q.addBindValue(maxSeverity);
    q.addBindValue(findingsJson);
    q.addBindValue(eventId);
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

QList<ExtensionRow> Database::extensionsForProfile(qint64 profileId) {
    QList<ExtensionRow> out;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT %1 FROM extensions WHERE profile_id = ? ORDER BY name")
                  .arg(QLatin1StringView(kExtensionCols)));
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

}  // namespace extwatch
