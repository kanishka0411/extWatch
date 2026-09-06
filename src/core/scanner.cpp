#include "core/scanner.h"

#include <QDir>
#include <QJsonArray>
#include <QJsonDocument>

#include "core/blobstore.h"
#include "core/chrometime.h"
#include "core/database.h"
#include "core/analyzer.h"
#include "core/hashing.h"
#include "core/inventory.h"
#include "core/jsonutil.h"
#include "extwatch/version.h"

namespace extwatch {

QString defaultDataDir() {
    const QString override = qEnvironmentVariable("EXTWATCH_DATA_DIR");
    if (!override.isEmpty()) {
        return QDir::cleanPath(override);
    }
#if defined(Q_OS_MACOS)
    return QDir::homePath() + QStringLiteral("/Library/Application Support/ExtWatch");
#elif defined(Q_OS_WIN)
    const QString local = QDir::fromNativeSeparators(qEnvironmentVariable("LOCALAPPDATA"));
    return (local.isEmpty() ? QDir::homePath() : local) + QStringLiteral("/ExtWatch");
#else
    const QString base = qEnvironmentVariable("XDG_DATA_HOME", QDir::homePath() + QStringLiteral("/.local/share"));
    return base + QStringLiteral("/extwatch");
#endif
}

QString databasePath(const QString& dataDir) {
    return dataDir + QStringLiteral("/extwatch.sqlite");
}

QString ScanEvent::headline() const {
    if (!fromVersion.isEmpty() && !toVersion.isEmpty() && fromVersion != toVersion) {
        return QStringLiteral("%1 %2 → %3").arg(extName, fromVersion, toVersion);
    }
    if (!toVersion.isEmpty()) {
        return QStringLiteral("%1 %2").arg(extName, toVersion);
    }
    return extName;
}

QString ScanEvent::summary() const {
    QString base;
    if (kind == QStringLiteral("baseline")) {
        base = QStringLiteral("%1 %2 recorded as baseline").arg(extName, toVersion);
    } else if (kind == QStringLiteral("updated")) {
        base = QStringLiteral("%1 updated %2 → %3").arg(extName, fromVersion, toVersion);
    } else if (kind == QStringLiteral("pending_version")) {
        base = QStringLiteral("%1 %2 downloaded, activates when idle").arg(extName, toVersion);
    } else if (kind == QStringLiteral("enabled")) {
        return QStringLiteral("%1 was enabled").arg(extName);
    } else if (kind == QStringLiteral("disabled")) {
        return QStringLiteral("%1 was disabled").arg(extName);
    } else if (kind == QStringLiteral("removed")) {
        return QStringLiteral("%1 was removed").arg(extName);
    } else {
        base = QStringLiteral("%1: %2").arg(extName, kind);
    }
    if (!findingsSummary.isEmpty() && kind != QStringLiteral("baseline")) {
        base += QStringLiteral(": ") + findingsSummary;
    }
    return base;
}

int ScanResult::profileCount() const {
    int n = 0;
    for (const BrowserReport& b : browsers) {
        n += static_cast<int>(b.profiles.size());
    }
    return n;
}

int ScanResult::extensionCount() const {
    int n = 0;
    for (const BrowserReport& b : browsers) {
        for (const ProfileReport& p : b.profiles) {
            n += static_cast<int>(p.extensions.size());
        }
    }
    return n;
}

namespace {

QJsonValue dateOrNull(const std::optional<QDateTime>& dt) {
    return dt ? QJsonValue(dt->toUTC().toString(Qt::ISODate)) : QJsonValue();
}

QJsonObject versionToJson(const VersionReport& v) {
    QJsonObject o;
    o.insert(QStringLiteral("version"), v.version);
    o.insert(QStringLiteral("dir"), v.dirName);
    o.insert(QStringLiteral("path"), v.path);
    o.insert(QStringLiteral("active"), v.active);
    o.insert(QStringLiteral("newly_seen"), v.newlySeen);
    if (!v.treeHash.isEmpty()) {
        o.insert(QStringLiteral("tree_hash"), QStringLiteral("sha256:") + v.treeHash);
    }
    o.insert(QStringLiteral("files"), v.fileCount);
    o.insert(QStringLiteral("bytes"), v.bytes);
    o.insert(QStringLiteral("has_webstore_metadata"), v.hasWebstoreMetadata);
    o.insert(QStringLiteral("key_matches_id"), v.keyMatchesId);
    o.insert(QStringLiteral("manifest"), v.manifest);
    if (!v.warnings.isEmpty()) {
        o.insert(QStringLiteral("warnings"), fromStringList(v.warnings));
    }
    return o;
}

QJsonObject extensionToJson(const ExtensionReport& e) {
    QJsonObject o;
    o.insert(QStringLiteral("id"), e.id);
    o.insert(QStringLiteral("name"), e.name);
    o.insert(QStringLiteral("enabled"), e.enabled);
    o.insert(QStringLiteral("disable_reasons"), fromStringList(e.disableReasons));
    o.insert(QStringLiteral("location"), e.locationId);
    o.insert(QStringLiteral("from_webstore"), e.fromWebstore);
    o.insert(QStringLiteral("unpacked"), e.unpacked);
    o.insert(QStringLiteral("update_url"), e.updateUrl);
    o.insert(QStringLiteral("active_version"), e.activeVersion);
    o.insert(QStringLiteral("install_time"), dateOrNull(e.installTime));
    o.insert(QStringLiteral("update_time"), dateOrNull(e.updateTime));
    QJsonArray versions;
    for (const VersionReport& v : e.versions) {
        versions.append(versionToJson(v));
    }
    o.insert(QStringLiteral("versions"), versions);
    if (!e.notes.isEmpty()) {
        o.insert(QStringLiteral("notes"), fromStringList(e.notes));
    }
    return o;
}

QJsonObject eventToJson(const ScanEvent& e) {
    QJsonObject o;
    o.insert(QStringLiteral("kind"), e.kind);
    o.insert(QStringLiteral("browser"), e.browserKind);
    o.insert(QStringLiteral("profile"), e.profileDir);
    o.insert(QStringLiteral("profile_name"), e.profileName);
    o.insert(QStringLiteral("id"), e.extId);
    o.insert(QStringLiteral("name"), e.extName);
    if (!e.fromVersion.isEmpty()) {
        o.insert(QStringLiteral("from_version"), e.fromVersion);
    }
    if (!e.toVersion.isEmpty()) {
        o.insert(QStringLiteral("to_version"), e.toVersion);
    }
    if (e.eventRowId) {
        o.insert(QStringLiteral("event_id"), *e.eventRowId);
    }
    if (!e.maxSeverity.isEmpty()) {
        o.insert(QStringLiteral("max_severity"), e.maxSeverity);
        o.insert(QStringLiteral("findings_summary"), e.findingsSummary);
        o.insert(QStringLiteral("findings"), findingsToJson(e.findings));
    }
    o.insert(QStringLiteral("summary"), e.summary());
    return o;
}

struct PersistContext {
    Database* db = nullptr;
    BlobStore* blobs = nullptr;
    qint64 now = 0;
};

// Records one extension of one profile into the database and turns differences against the
// previous scan into events.
void persistExtension(PersistContext& ctx, qint64 profileId, const InstalledExtension& ext,
                      ExtensionReport& report, const BrowserReport& browser,
                      const Profile& profile, QList<ScanEvent>& events) {
    Database& db = *ctx.db;
    const std::optional<ExtensionRow> before = db.findExtension(profileId, ext.id);
    const qint64 extensionId = db.upsertExtension(profileId, ext.id, report.name, report.location,
                                                  report.fromWebstore, report.enabled, ctx.now);
    if (extensionId < 0) {
        report.notes.append(QStringLiteral("database error: %1").arg(db.lastError()));
        return;
    }
    report.extensionRowId = extensionId;

    auto makeEvent = [&](const QString& kind) {
        ScanEvent ev;
        ev.kind = kind;
        ev.browserKind = browserKindId(browser.install.kind);
        ev.browserName = browser.install.displayName;
        ev.profileDir = profile.dirName;
        ev.profileName = profile.displayName;
        ev.extId = ext.id;
        ev.extName = report.name;
        ev.extensionRowId = extensionId;
        return ev;
    };
    auto storeEvent = [&](ScanEvent& ev) {
        EventRow row;
        row.extensionId = extensionId;
        row.kind = ev.kind;
        row.fromVersionId = ev.fromVersionRowId;
        row.toVersionId = ev.toVersionRowId;
        row.at = ctx.now;
        const qint64 id = db.insertEvent(row);
        if (id >= 0) {
            ev.eventRowId = id;
        }
        events.append(ev);
    };

    std::optional<qint64> previousCurrent = before ? before->currentVersionId : std::nullopt;
    QString previousVersion;
    if (previousCurrent) {
        if (const std::optional<VersionRow> pv = db.versionById(*previousCurrent)) {
            previousVersion = pv->version;
        }
    }

    const QString activeVersion = ext.activeVersion();
    for (VersionReport& vr : report.versions) {
        if (vr.treeHash.isEmpty()) {
            continue;  // hashing disabled: nothing to archive
        }
        std::optional<qint64> versionId = db.findVersionByTreeHash(extensionId, vr.treeHash);
        if (!versionId) {
            const VersionDir* vd = nullptr;
            for (const VersionDir& candidate : ext.versions) {
                if (candidate.dirName == vr.dirName) {
                    vd = &candidate;
                }
            }
            VersionRow row;
            row.extensionId = extensionId;
            row.version = vr.version;
            row.dirName = vr.dirName;
            row.treeHash = vr.treeHash;
            row.firstSeen = ctx.now;
            row.lastSeen = ctx.now;
            if (vr.active) {
                row.activatedAt = ctx.now;
            }
            row.manifestJson = QString::fromUtf8(QJsonDocument(vr.manifest).toJson(QJsonDocument::Compact));
            row.fileCount = vr.fileCount;
            row.bytes = vr.bytes;
            row.keyMatchesId = vr.keyMatchesId;
            row.hasWebstoreMetadata = vr.hasWebstoreMetadata;
            const qint64 id = db.insertVersion(row);
            if (id < 0) {
                vr.warnings.append(QStringLiteral("database error: %1").arg(db.lastError()));
                continue;
            }
            versionId = id;
            vr.newlySeen = true;
            if (vd) {
                db.insertFiles(id, vr.files);
                for (const FileEntry& f : vr.files) {
                    QString err;
                    if (!ctx.blobs->put(vd->path + u'/' + f.relPath, f.sha256, &err)) {
                        vr.warnings.append(err);
                    }
                }
            }
        } else {
            db.touchVersion(*versionId, ctx.now, vr.active);
        }
        vr.versionRowId = versionId;

        if (vr.active) {
            if (!previousCurrent) {
                ScanEvent ev = makeEvent(QStringLiteral("baseline"));
                ev.toVersion = vr.version;
                ev.toVersionRowId = versionId;
                storeEvent(ev);
                db.setCurrentVersion(extensionId, versionId);
            } else if (*previousCurrent != *versionId) {
                ScanEvent ev = makeEvent(QStringLiteral("updated"));
                ev.fromVersion = previousVersion;
                ev.toVersion = vr.version;
                ev.fromVersionRowId = previousCurrent;
                ev.toVersionRowId = versionId;
                storeEvent(ev);
                db.setCurrentVersion(extensionId, versionId);
            }
        } else if (vr.newlySeen && previousCurrent &&
                   compareVersions(vr.version, activeVersion) > 0) {
            ScanEvent ev = makeEvent(QStringLiteral("pending_version"));
            ev.fromVersion = activeVersion;
            ev.toVersion = vr.version;
            ev.fromVersionRowId = previousCurrent;
            ev.toVersionRowId = versionId;
            storeEvent(ev);
        }
    }

    if (before && before->enabled != report.enabled) {
        ScanEvent ev = makeEvent(report.enabled ? QStringLiteral("enabled") : QStringLiteral("disabled"));
        ev.toVersion = activeVersion;
        storeEvent(ev);
    }
}

void recordRemovals(PersistContext& ctx, qint64 profileId, const BrowserReport& browser,
                    const Profile& profile, QList<ScanEvent>& events) {
    Database& db = *ctx.db;
    for (const ExtensionRow& row : db.extensionsForProfile(profileId)) {
        if (row.lastSeen >= ctx.now) {
            continue;
        }
        const QList<EventRow> history = db.eventsForExtension(row.id);
        if (!history.isEmpty() && history.last().kind == QStringLiteral("removed")) {
            continue;
        }
        ScanEvent ev;
        ev.kind = QStringLiteral("removed");
        ev.browserKind = browserKindId(browser.install.kind);
        ev.browserName = browser.install.displayName;
        ev.profileDir = profile.dirName;
        ev.profileName = profile.displayName;
        ev.extId = row.extId;
        ev.extName = row.name;
        ev.extensionRowId = row.id;
        if (row.currentVersionId) {
            if (const std::optional<VersionRow> v = db.versionById(*row.currentVersionId)) {
                ev.fromVersion = v->version;
                ev.fromVersionRowId = v->id;
            }
        }
        EventRow er;
        er.extensionId = row.id;
        er.kind = ev.kind;
        er.fromVersionId = ev.fromVersionRowId;
        er.at = ctx.now;
        const qint64 id = db.insertEvent(er);
        if (id >= 0) {
            ev.eventRowId = id;
        }
        events.append(ev);
    }
}

ExtensionReport buildReport(const InstalledExtension& ext, bool computeHashes) {
    ExtensionReport r;
    r.id = ext.id;
    r.name = ext.displayName();
    r.activeVersion = ext.activeVersion();
    r.location = ext.location();
    r.locationId = installLocationId(r.location);
    r.enabled = ext.enabled();
    r.unpacked = ext.unpacked();
    r.notes = ext.notes;
    if (ext.record) {
        r.fromWebstore = ext.record->fromWebstore;
        r.updateUrl = ext.record->updateUrl;
        r.disableReasons = ext.record->disableReasonNames();
        if (ext.record->firstInstallTime) {
            r.installTime = chromeTimeToDateTime(*ext.record->firstInstallTime);
        }
        if (ext.record->lastUpdateTime) {
            r.updateTime = chromeTimeToDateTime(*ext.record->lastUpdateTime);
        }
    }
    for (const VersionDir& vd : ext.versions) {
        VersionReport vr;
        vr.dirName = vd.dirName;
        vr.version = vd.version;
        vr.path = vd.path;
        vr.active = vd.isActive;
        vr.hasWebstoreMetadata = vd.hasWebstoreMetadata;
        vr.keyMatchesId = vd.keyMatchesId;
        vr.manifest = vd.manifest.toJson();
        if (!vd.manifest.valid) {
            vr.warnings.append(vd.manifest.error);
        }
        if (r.updateUrl.isEmpty()) {
            r.updateUrl = vd.manifest.updateUrl;
        }
        if (computeHashes) {
            const TreeSnapshot snap = hashTree(vd.path);
            vr.treeHash = toHex(snap.treeHash);
            vr.fileCount = static_cast<int>(snap.files.size());
            vr.bytes = snap.totalBytes;
            vr.warnings += snap.warnings;
            vr.files = snap.files;
        }
        r.versions.append(vr);
    }
    return r;
}

}  // namespace

ScanResult runScan(const ScanOptions& options) {
    ScanResult result;
    result.scannedAt = QDateTime::currentDateTimeUtc();
    const qint64 now = result.scannedAt.toSecsSinceEpoch();

    const bool persist = options.persist && options.computeHashes;
    Database db;
    std::optional<BlobStore> blobs;
    PersistContext ctx;
    if (persist) {
        const QString dataDir = options.dataDir.isEmpty() ? defaultDataDir() : options.dataDir;
        result.dataDir = dataDir;
        QString err;
        if (!db.open(databasePath(dataDir), &err)) {
            result.warnings.append(QStringLiteral("cannot open database: %1").arg(err));
        } else {
            blobs.emplace(dataDir);
            ctx.db = &db;
            ctx.blobs = &*blobs;
            ctx.now = now;
        }
    }
    const bool canPersist = ctx.db != nullptr;

    const QList<BrowserInstall> candidates =
        options.candidates.isEmpty() ? knownBrowserLocations() : options.candidates;
    for (const DiscoveredBrowser& found : discoverBrowsers(candidates)) {
        if (options.onlyBrowser && *options.onlyBrowser != found.install.kind) {
            continue;
        }
        BrowserReport br;
        br.install = found.install;
        if (canPersist) {
            const qint64 id = db.upsertBrowser(browserKindId(found.install.kind),
                                               found.install.userDataDir,
                                               found.install.displayName, now);
            if (id >= 0) {
                br.browserRowId = id;
            }
        }
        for (const Profile& profile : found.profiles) {
            if (!options.onlyProfile.isEmpty() && profile.dirName != options.onlyProfile &&
                profile.displayName != options.onlyProfile) {
                continue;
            }
            ProfileReport pr;
            pr.profile = profile;
            const ProfileInventory inv = inventoryProfile(profile);
            pr.warnings = inv.warnings;
            std::optional<qint64> profileId;
            if (canPersist && br.browserRowId) {
                const qint64 id = db.upsertProfile(*br.browserRowId, profile.dirName,
                                                   profile.displayName, now);
                if (id >= 0) {
                    profileId = id;
                    pr.profileRowId = id;
                }
            }
            if (profileId) {
                db.transaction();
            }
            for (const InstalledExtension& ext : inv.extensions) {
                ExtensionReport report = buildReport(ext, options.computeHashes);
                if (profileId) {
                    persistExtension(ctx, *profileId, ext, report, br, profile, result.events);
                }
                pr.extensions.append(report);
            }
            if (profileId) {
                recordRemovals(ctx, *profileId, br, profile, result.events);
                db.commit();
            }
            br.profiles.append(pr);
        }
        result.browsers.append(br);
    }

    if (canPersist && options.analyze) {
        for (ScanEvent& ev : result.events) {
            if (!ev.eventRowId || !ev.toVersionRowId) {
                continue;
            }
            ev.findings = analyzeEvent(db, *blobs, *ev.eventRowId);
            ev.maxSeverity = severityId(maxSeverity(ev.findings));
            ev.findingsSummary = findingsSummary(ev.findings);
        }
    }
    return result;
}

QJsonObject ScanResult::toJson() const {
    QJsonObject root;
    QJsonObject meta;
    meta.insert(QStringLiteral("version"), QStringLiteral(EXTWATCH_VERSION));
    meta.insert(QStringLiteral("schema"), EXTWATCH_SCHEMA_VERSION);
    meta.insert(QStringLiteral("scanned_at"), scannedAt.toString(Qt::ISODate));
    if (!dataDir.isEmpty()) {
        meta.insert(QStringLiteral("data_dir"), dataDir);
    }
    root.insert(QStringLiteral("extwatch"), meta);

    QJsonArray browsersJson;
    for (const BrowserReport& b : browsers) {
        QJsonObject bo;
        bo.insert(QStringLiteral("kind"), browserKindId(b.install.kind));
        bo.insert(QStringLiteral("name"), b.install.displayName);
        bo.insert(QStringLiteral("user_data_dir"), b.install.userDataDir);
        QJsonArray profilesJson;
        for (const ProfileReport& p : b.profiles) {
            QJsonObject po;
            po.insert(QStringLiteral("dir"), p.profile.dirName);
            po.insert(QStringLiteral("name"), p.profile.displayName);
            po.insert(QStringLiteral("path"), p.profile.path);
            QJsonArray exts;
            for (const ExtensionReport& e : p.extensions) {
                exts.append(extensionToJson(e));
            }
            po.insert(QStringLiteral("extensions"), exts);
            if (!p.warnings.isEmpty()) {
                po.insert(QStringLiteral("warnings"), fromStringList(p.warnings));
            }
            profilesJson.append(po);
        }
        bo.insert(QStringLiteral("profiles"), profilesJson);
        browsersJson.append(bo);
    }
    root.insert(QStringLiteral("browsers"), browsersJson);

    QJsonArray eventsJson;
    for (const ScanEvent& e : events) {
        eventsJson.append(eventToJson(e));
    }
    root.insert(QStringLiteral("events"), eventsJson);
    if (!warnings.isEmpty()) {
        root.insert(QStringLiteral("warnings"), fromStringList(warnings));
    }
    return root;
}

}  // namespace extwatch
