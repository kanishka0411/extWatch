#include <QTemporaryDir>
#include <QtTest>

#include "core/blobstore.h"
#include "core/database.h"
#include "core/discovery.h"
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
};

QTEST_GUILESS_MAIN(TestInventory)
#include "test_inventory.moc"
