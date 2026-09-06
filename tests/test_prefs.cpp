#include <QJsonDocument>
#include <QTemporaryDir>
#include <QtTest>

#include "core/prefs.h"
#include "testutil.h"

using namespace extwatch;

namespace {

// Test JSON is written with single quotes so that moc's scanner is not confused by raw
// string literals; they are swapped for double quotes here.
QJsonObject obj(const char* json) {
    return QJsonDocument::fromJson(QByteArray(json).replace('\'', '"')).object();
}

}  // namespace

class TestPrefs : public QObject {
    Q_OBJECT
private slots:
    void newShapeUsesDisableReasonsList() {
        const ExtensionRecord r = parseExtensionRecord(
            QStringLiteral("cjpalhdlnbpafiamejdnhcphjbkeiagm"),
            obj("{'path':'cjpalhdlnbpafiamejdnhcphjbkeiagm/2.1.7_0','location':1, 'from_webstore':true,'disable_reasons':[], 'first_install_time':'13411699200000000','last_update_time':'13411699200000000', 'manifest':{'name':'uBlock Origin Lite','version':'2.1.7', 'update_url':'https://clients2.google.com/service/update2/crx'}, 'active_permissions':{'api':['storage','declarativeNetRequest'], 'explicit_host':['<all_urls>']}}"));
        QVERIFY(r.enabled());
        QVERIFY(r.disableReasonsPresent);
        QVERIFY(!r.state.has_value());
        QCOMPARE(r.manifestName, QStringLiteral("uBlock Origin Lite"));
        QCOMPARE(r.manifestVersion, QStringLiteral("2.1.7"));
        QCOMPARE(r.location, 1);
        QVERIFY(r.fromWebstore);
        QVERIFY(!r.hasAbsolutePath());
        QCOMPARE(r.firstInstallTime.value(), 13411699200000000LL);
        QCOMPARE(r.activePermissions.api, QStringList({QStringLiteral("storage"), QStringLiteral("declarativeNetRequest")}));
        QCOMPARE(r.activePermissions.explicitHosts, QStringList{QStringLiteral("<all_urls>")});
    }

    void newShapeDisabledByUser() {
        const ExtensionRecord r = parseExtensionRecord(
            QStringLiteral("cjpalhdlnbpafiamejdnhcphjbkeiagm"),
            obj("{'path':'x/1_0','location':1,'disable_reasons':[1]}"));
        QVERIFY(!r.enabled());
        QCOMPARE(r.disableReasonNames(), QStringList{QStringLiteral("user_action")});
    }

    void legacyShapeUsesStateAndBitmask() {
        const ExtensionRecord enabled = parseExtensionRecord(
            QStringLiteral("a"), obj("{'path':'a/1_0','location':1,'state':1}"));
        QVERIFY(enabled.enabled());
        const ExtensionRecord disabled = parseExtensionRecord(
            QStringLiteral("a"), obj("{'path':'a/1_0','location':1,'state':0,'disable_reasons':1026}"));
        QVERIFY(!disabled.enabled());
        QCOMPARE(disabled.disableReasons, QList<int>({2, 1024}));
        QCOMPARE(disabled.disableReasonNames(),
                 QStringList({QStringLiteral("permissions_increase"), QStringLiteral("corrupted")}));
    }

    void windowsPathsAreNormalized() {
        const ExtensionRecord r = parseExtensionRecord(
            QStringLiteral("a"), obj("{'path':'abcdefghijklmnopabcdefghijklmnop\\\\1.0_0','location':1}"));
        QCOMPARE(r.path, QStringLiteral("abcdefghijklmnopabcdefghijklmnop/1.0_0"));
        QVERIFY(!r.hasAbsolutePath());
        const ExtensionRecord unpacked = parseExtensionRecord(
            QStringLiteral("a"), obj("{'path':'/Users/me/dev/my-extension','location':4}"));
        QVERIFY(unpacked.hasAbsolutePath());
    }

    void locationsAndInternals() {
        QCOMPARE(installLocationId(1), QStringLiteral("internal"));
        QCOMPARE(installLocationId(4), QStringLiteral("unpacked"));
        QCOMPARE(installLocationId(42), QStringLiteral("unknown_42"));
        QVERIFY(isBrowserInternalLocation(5));
        QVERIFY(isBrowserInternalLocation(10));
        QVERIFY(!isBrowserInternalLocation(1));
    }

    void readsProfileAndSkipsInvalidIds() {
        QTemporaryDir tmp;
        QVERIFY(tmp.isValid());
        testutil::makeFakeUserDataDir(tmp.path(), QStringLiteral("Default"), QStringLiteral("1.0.0"));
        const ProfilePrefs prefs = readProfilePrefs(tmp.path() + QStringLiteral("/Default"));
        QVERIFY(prefs.warnings.isEmpty());
        QCOMPARE(prefs.extensions.size(), 2);  // fixture + component
        QVERIFY(prefs.extensions.contains(testutil::fixtureExtensionId()));
        QVERIFY(prefs.extensions.value(testutil::fixtureExtensionId()).enabled());
    }
};

QTEST_GUILESS_MAIN(TestPrefs)
#include "test_prefs.moc"
