#include <QtTest>

#include "core/chrometime.h"

using namespace extwatch;

class TestChromeTime : public QObject {
    Q_OBJECT
private slots:
    void unixEpoch() {
        const QDateTime dt = chromeTimeToDateTime(kWindowsToUnixEpochSeconds * 1000000);
        QCOMPARE(dt.toSecsSinceEpoch(), 0);
    }

    void knownDate() {
        // 2026-01-01T00:00:00Z = 1767225600 unix seconds
        const QDateTime dt = chromeTimeToDateTime(13411699200000000LL);
        QCOMPARE(dt, QDateTime(QDate(2026, 1, 1), QTime(0, 0), QTimeZone::UTC));
        QCOMPARE(dateTimeToChromeTime(dt), 13411699200000000LL);
    }

    void parsesStringsAndNumbers() {
        QCOMPARE(parseChromeTime(QJsonValue(QStringLiteral("13411699200000000"))).value(),
                 13411699200000000LL);
        QCOMPARE(parseChromeTime(QJsonValue(13411699200000000.0)).value(), 13411699200000000LL);
        QVERIFY(!parseChromeTime(QJsonValue(QStringLiteral("0"))).has_value());
        QVERIFY(!parseChromeTime(QJsonValue(QStringLiteral("garbage"))).has_value());
        QVERIFY(!parseChromeTime(QJsonValue()).has_value());
    }
};

QTEST_GUILESS_MAIN(TestChromeTime)
#include "test_chrometime.moc"
