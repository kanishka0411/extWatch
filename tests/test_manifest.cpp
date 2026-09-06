#include <QJsonDocument>
#include <QtTest>

#include "core/manifest.h"
#include "testutil.h"

using namespace extwatch;

class TestManifest : public QObject {
    Q_OBJECT
private slots:
    void readsFixtureAndResolvesI18n() {
        const ManifestFacts m = readManifest(testutil::fixtureExtensionDir(QStringLiteral("1.0.0")));
        QVERIFY(m.valid);
        QCOMPARE(m.manifestVersion, 3);
        QCOMPARE(m.name, QStringLiteral("Screenshot Tool"));
        QVERIFY(m.description.startsWith(QStringLiteral("Capture")));
        QCOMPARE(m.version, QStringLiteral("1.0.0"));
        QCOMPARE(m.permissions, QStringList({QStringLiteral("activeTab"), QStringLiteral("storage")}));
        QVERIFY(m.hostPermissions.isEmpty());
        QCOMPARE(m.backgroundServiceWorker, QStringLiteral("sw.js"));
        QCOMPARE(m.contentScripts.size(), 1);
        QCOMPARE(m.contentScripts.first().matches, QStringList{QStringLiteral("https://*.example.com/*")});
        QCOMPARE(m.iconPath, QStringLiteral("icon128.png"));
        QCOMPARE(m.updateUrl, QStringLiteral("https://clients2.google.com/service/update2/crx"));
    }

    void maliciousVersionFacts() {
        const ManifestFacts m = readManifest(testutil::fixtureExtensionDir(QStringLiteral("1.2.0")));
        QVERIFY(m.valid);
        QCOMPARE(m.hostPermissions, QStringList{QStringLiteral("<all_urls>")});
        QVERIFY(m.permissions.contains(QStringLiteral("declarativeNetRequest")));
        QCOMPARE(m.dnrRuleResources.size(), 1);
        QCOMPARE(m.dnrRuleResources.first().path, QStringLiteral("rules.json"));
        QVERIFY(m.contentScripts.first().allFrames);
    }

    void mv2HostPatternsMoveOutOfPermissions() {
        const QJsonObject raw = QJsonDocument::fromJson(QByteArray("{ 'manifest_version': 2, 'name': 'Old', 'version': '0.9', 'permissions': ['tabs', 'https://*/*', '<all_urls>', {'usbDevices': []}], 'optional_permissions': ['http://example.org/*', 'bookmarks'], 'background': {'scripts': ['bg.js'], 'persistent': false}, 'content_security_policy': 'script-src https://cdn.example.com; object-src none' }").replace('\'', '"')).object();
        const ManifestFacts m = parseManifest(raw, [](const QString& s) { return s; });
        QCOMPARE(m.permissions, QStringList({QStringLiteral("tabs"), QStringLiteral("{\"usbDevices\":[]}")}));
        QCOMPARE(m.hostPermissions, QStringList({QStringLiteral("https://*/*"), QStringLiteral("<all_urls>")}));
        QCOMPARE(m.optionalPermissions, QStringList{QStringLiteral("bookmarks")});
        QCOMPARE(m.optionalHostPermissions, QStringList{QStringLiteral("http://example.org/*")});
        QCOMPARE(m.backgroundScripts, QStringList{QStringLiteral("bg.js")});
        QVERIFY(m.backgroundPersistent.has_value());
        QVERIFY(!*m.backgroundPersistent);
        QVERIFY(m.contentSecurityPolicy.isString());
    }

    void i18nIsCaseInsensitiveAndKeepsUnknowns() {
        QJsonObject messages;
        QJsonObject msg;
        msg.insert(QStringLiteral("message"), QStringLiteral("Hello"));
        messages.insert(QStringLiteral("greeting"), msg);
        QCOMPARE(resolveI18n(QStringLiteral("__MSG_Greeting__ world"), messages), QStringLiteral("Hello world"));
        QCOMPARE(resolveI18n(QStringLiteral("__MSG_missing__"), messages), QStringLiteral("__MSG_missing__"));
        QCOMPARE(resolveI18n(QStringLiteral("plain"), messages), QStringLiteral("plain"));
    }

    void missingManifestIsInvalid() {
        const ManifestFacts m = readManifest(QStringLiteral("/nonexistent/path"));
        QVERIFY(!m.valid);
        QVERIFY(!m.error.isEmpty());
    }

    void toJsonRoundTripsKeyFields() {
        const ManifestFacts m = readManifest(testutil::fixtureExtensionDir(QStringLiteral("1.2.0")));
        const QJsonObject j = m.toJson();
        QCOMPARE(j.value(QStringLiteral("name")).toString(), QStringLiteral("Screenshot Tool"));
        QCOMPARE(j.value(QStringLiteral("host_permissions")).toArray().size(), 1);
        QVERIFY(j.value(QStringLiteral("has_key")).toBool());
        QCOMPARE(j.value(QStringLiteral("dnr_rule_resources")).toArray().size(), 1);
    }
};

QTEST_GUILESS_MAIN(TestManifest)
#include "test_manifest.moc"
