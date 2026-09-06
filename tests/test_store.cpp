#include <QtTest>

#include "core/storemeta.h"
#include "testutil.h"

using namespace extwatch;

class TestStore : public QObject {
    Q_OBJECT
private slots:
    void parsesRealListingFixture() {
        QFile f(testutil::fixturesDir() + QStringLiteral("/store/ublock-origin-lite.html"));
        QVERIFY(f.open(QIODevice::ReadOnly));
        const StoreListing l = parseStoreListing(QStringLiteral("ddkjiahejlhfcafbddmgiahcphecmpfh"), f.readAll(), 200);
        QVERIFY(l.found);
        QCOMPARE(l.name, QStringLiteral("uBlock Origin Lite"));
        QCOMPARE(l.developer, QStringLiteral("Raymond Hill (gorhill)"));
        QCOMPARE(l.developerEmail, QStringLiteral("ubo@raymondhill.net"));
        QCOMPARE(l.version, QStringLiteral("2026.901.1442"));
        QCOMPARE(l.updated, QStringLiteral("September 1, 2026"));
        QCOMPARE(l.size, QStringLiteral("9.22MiB"));
        QCOMPARE(l.rating, QStringLiteral("4.5"));
        QCOMPARE(l.traderStatus, QStringLiteral("non-trader"));
        const StoreListing back = StoreListing::fromJson(l.toJson());
        QCOMPARE(back.developer, l.developer);
        QCOMPARE(back.version, l.version);
        QVERIFY(back.found);
    }

    void notFoundIsReported() {
        const StoreListing l = parseStoreListing(QStringLiteral("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), QByteArray("<html>nothing</html>"), 404);
        QVERIFY(!l.found);
        QVERIFY(l.gone);
        QCOMPARE(l.httpStatus, 404);
        const StoreListing generic = parseStoreListing(QStringLiteral("x"), QByteArray("<html><head><meta property=\"og:title\" content=\"Chrome Web Store\"></head><body></body></html>"), 200);
        QVERIFY(!generic.found);
        QVERIFY(generic.gone);
        const StoreListing empty = parseStoreListing(QStringLiteral("x"), QByteArray("<html><body>unrelated</body></html>"), 200);
        QVERIFY(!empty.found);
        QVERIFY(!empty.gone);
        QVERIFY(!empty.error.isEmpty());
    }

    void listingUrl() {
        QCOMPARE(storeListingUrl(QStringLiteral("abc")).toString(), QStringLiteral("https://chromewebstore.google.com/detail/abc"));
    }
};

QTEST_GUILESS_MAIN(TestStore)
#include "test_store.moc"
