#include <QtTest>

#include "core/crxid.h"
#include "core/manifest.h"
#include "testutil.h"

using namespace extwatch;

class TestCrxId : public QObject {
    Q_OBJECT
private slots:
    void derivesIdFromFixtureKey() {
        const ManifestFacts m = readManifest(testutil::fixtureExtensionDir(QStringLiteral("1.0.0")));
        QVERIFY(m.valid);
        QVERIFY(!m.key.isEmpty());
        const QString expected = testutil::fixtureExtensionId();
        QCOMPARE(expected.size(), 32);
        QCOMPARE(extensionIdFromManifestKey(m.key), expected);
        QVERIFY(isValidExtensionId(expected));
    }

    void idIsLowercaseAtoP() {
        const QString id = extensionIdFromPublicKey(QByteArrayLiteral("not really a key"));
        QCOMPARE(id.size(), 32);
        for (const QChar c : id) {
            QVERIFY(c >= u'a' && c <= u'p');
        }
    }

    void rejectsBadIds() {
        QVERIFY(!isValidExtensionId(QStringLiteral("")));
        QVERIFY(!isValidExtensionId(QStringLiteral("abc")));
        QVERIFY(!isValidExtensionId(QStringLiteral("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")));
        QVERIFY(isValidExtensionId(QStringLiteral("cjpalhdlnbpafiamejdnhcphjbkeiagm")));
        QVERIFY(extensionIdFromManifestKey(QString()).isEmpty());
    }
};

QTEST_GUILESS_MAIN(TestCrxId)
#include "test_crxid.moc"
