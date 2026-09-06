#include "core/scanner.h"

#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QSet>
#include <QThread>
#include <QJsonDocument>

#include "core/blobstore.h"
#include "core/chrometime.h"
#include "core/database.h"
#include "core/analyzer.h"
#include "core/rules.h"
#include "core/signature.h"
#include "core/hashing.h"
#include "core/inventory.h"
#include "core/jsonutil.h"
#include "extwatch/version.h"

namespace extwatch {

int scanExitCode(const ScanResult& result) {
    for (const ScanEvent& e : result.events) {
        if (e.kind != QStringLiteral("baseline") && e.maxSeverity == QStringLiteral("high")) {
            return 3;
        }
    }
    return result.warnings.isEmpty() ? 0 : 1;
}

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
    } else if (kind == QStringLiteral("modified_in_place")) {
        base = QStringLiteral("%1 %2: installed files changed without a version change").arg(extName, toVersion);
    } else if (kind == QStringLiteral("pending_version")) {
        base = QStringLiteral("%1 %2 downloaded, activates when idle").arg(extName, toVersion);
    } else if (kind == QStringLiteral("enabled")) {
        return QStringLiteral("%1 was enabled").arg(extName);
    } else if (kind == QStringLiteral("disabled")) {
        return QStringLiteral("%1 was disabled").arg(extName);
    } else if (kind == QStringLiteral("removed")) {
        return QStringLiteral("%1 was removed").arg(extName);
    } else if (kind == QStringLiteral("reinstalled")) {
        base = fromVersion == toVersion ? QStringLiteral("%1 %2 was installed again").arg(extName, toVersion)
                                        : QStringLiteral("%1 installed again at %2 (was %3)").arg(extName, toVersion, fromVersion);
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
    o.insert(QStringLiteral("settled"), v.settled);
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
    bool needsRescan = false;
    QSet<qint64> seenExtensions;  // extension rows visited by this scan; the rest may be gone
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
    if (extensionId >= 0) {
        ctx.seenExtensions.insert(extensionId);
    }
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

    // A row that a previous scan marked absent and that is back is a reinstall, even when the
    // bytes are identical; otherwise the return would leave no trace.
    const bool reappeared = before && !before->present;
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
        if (!vr.settled) {
            report.notes.append(QStringLiteral("%1 is still being written; will retry").arg(vr.dirName));
            ctx.needsRescan = true;
            continue;
        }
        std::optional<qint64> versionId = db.findVersionByTreeHash(extensionId, vr.treeHash);
        if (!versionId) {
            const VersionDir* vd = nullptr;
            for (const VersionDir& candidate : ext.versions) {
                if (candidate.dirName == vr.dirName) {
                    vd = &candidate;
                }
            }
            // 1. Archive every blob first; a file that changed since it was hashed is rejected.
            bool archived = vd != nullptr;
            if (vd) {
                for (const FileEntry& f : vr.files) {
                    QString err;
                    if (!ctx.blobs->put(vd->path + u'/' + f.relPath, f.sha256, &err)) {
                        vr.warnings.append(err);
                        archived = false;
                        break;
                    }
                }
            }
            if (!archived) {
                report.notes.append(QStringLiteral("%1 could not be archived completely; will retry").arg(vr.dirName));
                ctx.needsRescan = true;
                continue;
            }
            // 2. Record the snapshot in one transaction.
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
            row.statFingerprint = vr.fingerprint;
            row.state = QStringLiteral("complete");
            if (!db.transaction()) {
                vr.warnings.append(QStringLiteral("database error: %1").arg(db.lastError()));
                continue;
            }
            const qint64 id = db.insertVersion(row);
            if (id < 0 || !db.insertFiles(id, vr.files) || !db.commit()) {
                db.rollback();
                vr.warnings.append(QStringLiteral("database error: %1").arg(db.lastError()));
                ctx.needsRescan = true;
                continue;
            }
            versionId = id;
            vr.newlySeen = true;
        } else {
            db.touchVersion(*versionId, ctx.now, vr.active);
            if (!vr.fingerprint.isEmpty()) {
                db.setVersionFingerprint(*versionId, vr.fingerprint);
            }
        }
        vr.versionRowId = versionId;

        if (vr.active) {
            if (!previousCurrent) {
                ScanEvent ev = makeEvent(QStringLiteral("baseline"));
                ev.toVersion = vr.version;
                ev.toVersionRowId = versionId;
                storeEvent(ev);
                db.setCurrentVersion(extensionId, versionId);
            } else if (reappeared) {
                ScanEvent ev = makeEvent(QStringLiteral("reinstalled"));
                ev.fromVersion = previousVersion;
                ev.toVersion = vr.version;
                ev.fromVersionRowId = previousCurrent;
                ev.toVersionRowId = versionId;
                storeEvent(ev);
                db.setCurrentVersion(extensionId, versionId);
            } else if (*previousCurrent != *versionId) {
                // Same version string but different bytes is its own kind of event: nothing was
                // "updated", the installed files changed underneath the browser.
                const bool sameVersion = previousVersion == vr.version;
                ScanEvent ev = makeEvent(sameVersion ? QStringLiteral("modified_in_place") : QStringLiteral("updated"));
                ev.fromVersion = previousVersion;
                ev.toVersion = vr.version;
                ev.fromVersionRowId = previousCurrent;
                ev.toVersionRowId = versionId;
                storeEvent(ev);
                db.setCurrentVersion(extensionId, versionId);
            }
        } else if (vr.newlySeen && compareVersions(vr.version, activeVersion) > 0) {
            // Downloaded but not yet activated, also on the very first scan.
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
    for (const ExtensionRow& row : db.extensionsForProfile(profileId, /*presentOnly=*/true)) {
        if (ctx.seenExtensions.contains(row.id)) {
            continue;  // membership, not a timestamp: two scans in the same second stay correct
        }
        db.setExtensionPresent(row.id, false);
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

ExtensionReport buildReport(const InstalledExtension& ext, bool computeHashes, int settleSeconds,
                            const QHash<QString, VersionRow>& knownByDir, bool forceHash) {
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
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
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
            vr.fingerprint = directoryFingerprint(vd.path);
            const auto known = knownByDir.constFind(vd.dirName);
            if (!forceHash && known != knownByDir.constEnd() && !known->statFingerprint.isEmpty() &&
                known->statFingerprint == vr.fingerprint) {
                // Nothing on disk changed since this tree was archived: skip the hashing.
                vr.treeHash = known->treeHash;
                vr.fileCount = known->fileCount;
                vr.bytes = known->bytes;
                vr.reused = true;
            } else {
                const TreeSnapshot snap = hashTree(vd.path);
                vr.treeHash = toHex(snap.treeHash);
                vr.fileCount = static_cast<int>(snap.files.size());
                vr.bytes = snap.totalBytes;
                vr.warnings += snap.warnings;
                vr.files = snap.files;
                // A directory the browser is still writing must not be archived yet: files newer
                // than the settle window, or a tree that changed while it was being hashed.
                const bool recentlyWritten = nowMs - snap.newestMtimeMs < qint64(settleSeconds) * 1000;
                const bool changedMeanwhile = directoryFingerprint(vd.path) != vr.fingerprint;
                vr.settled = vd.manifest.valid && !recentlyWritten && !changedMeanwhile;
                if (changedMeanwhile) {
                    vr.fingerprint = QString();  // do not record a fingerprint we know is stale
                }
            }
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
            // The archive holds copies of other people's code and your browsing setup: keep it private.
            QFile::setPermissions(dataDir, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
            QFile::setPermissions(databasePath(dataDir), QFileDevice::ReadOwner | QFileDevice::WriteOwner);
            blobs.emplace(dataDir);
            ctx.db = &db;
            ctx.blobs = &*blobs;
            ctx.now = now;
        }
    }
    const bool canPersist = ctx.db != nullptr;

    // Unchanged trees are recognised by fingerprint; every fourth persisted scan, whichever process
    // runs it, re-hashes everything. The counter lives in the database so the tray and the CLI
    // share one policy.
    int scansSinceFullHash = 0;
    bool fullHash = options.forceHash || !options.computeHashes;
    if (canPersist && options.computeHashes) {
        scansSinceFullHash = db.metaValue(QStringLiteral("scans_since_full_hash")).toInt();
        fullHash = fullHash || scansSinceFullHash >= 3;
    }
    result.fullHash = fullHash && options.computeHashes;

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
            for (const InstalledExtension& ext : inv.extensions) {
                QHash<QString, VersionRow> known;
                if (profileId) {
                    if (const std::optional<ExtensionRow> row = db.findExtension(*profileId, ext.id)) {
                        for (const VersionRow& v : db.versionsForExtension(row->id)) {
                            known.insert(v.dirName, v);
                        }
                    }
                }
                ExtensionReport report = buildReport(ext, options.computeHashes, options.settleSeconds, known, fullHash);
                if (profileId) {
                    persistExtension(ctx, *profileId, ext, report, br, profile, result.events);
                }
                pr.extensions.append(report);
            }
            if (profileId) {
                recordRemovals(ctx, *profileId, br, profile, result.events);
            }
            br.profiles.append(pr);
        }
        result.browsers.append(br);
    }

    result.needsRescan = ctx.needsRescan;
    if (canPersist && options.computeHashes) {
        db.setMetaValue(QStringLiteral("scans_since_full_hash"), fullHash ? QStringLiteral("0") : QString::number(scansSinceFullHash + 1));
    }

    // Profiles the browser deleted (or a browser that was uninstalled) are never visited above.
    // Within the browsers this scan was asked to cover, a known profile that was not seen has
    // its extensions recorded as removed. Filtered scans leave everything else alone.
    if (canPersist && !options.onlyBrowser && options.onlyProfile.isEmpty()) {
        QSet<QString> scope;
        for (const BrowserInstall& c : candidates) {
            scope.insert(QDir::cleanPath(c.userDataDir));
        }
        QSet<qint64> seenProfiles;
        for (const BrowserReport& b : result.browsers) {
            for (const ProfileReport& p : b.profiles) {
                if (p.profileRowId) {
                    seenProfiles.insert(*p.profileRowId);
                }
            }
        }
        for (const BrowserRow& b : db.browsers()) {
            if (!scope.contains(QDir::cleanPath(b.userDataDir))) {
                continue;
            }
            for (const ProfileRow& p : db.profilesForBrowser(b.id)) {
                if (seenProfiles.contains(p.id)) {
                    continue;
                }
                BrowserReport br;
                br.install = {browserKindFromId(b.kind).value_or(BrowserKind::Chrome), b.displayName, b.userDataDir};
                recordRemovals(ctx, p.id, br, {p.dirName, p.displayName, QString()}, result.events);
            }
        }
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
        // Events left without findings by an earlier crash or interrupted run.
        for (const EventRow& e : db.unanalyzedEvents(20)) {
            analyzeEvent(db, *blobs, e.id);
        }
        // Findings from an older rules generation are redone from the (cached) signatures.
        for (const EventRow& e : db.staleFindingsEvents(kFindingsSchema, 50)) {
            analyzeEvent(db, *blobs, e.id);
        }
        // Signatures written by an older analyzer are recomputed from the archived blobs, a few
        // per scan, so an upgrade does not stall the first scan and old versions compare like
        // for like with new ones.
        int refreshed = 0;
        for (const VersionRow& v : db.allVersions()) {
            if (refreshed >= 8 || v.signatureJson.isEmpty()) {
                continue;
            }
            const QJsonObject json = QJsonDocument::fromJson(v.signatureJson.toUtf8()).object();
            if (json.value(QStringLiteral("schema")).toInt() != kSignatureSchema) {
                signatureForVersion(db, *blobs, v.id);
                ++refreshed;
            }
        }
    }

    // A directory that was still being written: wait for it to settle and look again.
    if (result.needsRescan && options.settleRetries > 0) {
        QThread::sleep(static_cast<unsigned>(qMax(1, options.settleSeconds)));
        ScanOptions retry = options;
        retry.settleRetries = options.settleRetries - 1;
        ScanResult second = runScan(retry);
        second.events = result.events + second.events;
        second.warnings = result.warnings + second.warnings;
        return second;
    }
    return result;
}

QJsonObject ScanResult::toJson() const {
    QJsonObject root;
    QJsonObject meta;
    meta.insert(QStringLiteral("version"), QStringLiteral(EXTWATCH_VERSION));
    meta.insert(QStringLiteral("schema"), EXTWATCH_SCHEMA_VERSION);
    meta.insert(QStringLiteral("scanned_at"), scannedAt.toString(Qt::ISODate));
    meta.insert(QStringLiteral("full_hash"), fullHash);
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
