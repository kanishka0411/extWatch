#include <QJsonDocument>
#include <QtTest>

#include "core/companion.h"
#include "core/crxid.h"
#include "core/nativemessaging.h"
#include "testutil.h"

using namespace extwatch;

class TestNativeMessaging : public QObject {
    Q_OBJECT
private slots:
    void framesRoundTrip() {
        QJsonObject a;
        a.insert(QStringLiteral("type"), QStringLiteral("hello"));
        a.insert(QStringLiteral("n"), 1);
        QJsonObject b;
        b.insert(QStringLiteral("type"), QStringLiteral("list"));
        QByteArray stream = frameNativeMessage(a) + frameNativeMessage(b);
        // Deliver in two chunks split inside the second frame.
        QByteArray buffer = stream.left(stream.size() - 5);
        QString error;
        QList<QJsonObject> frames = parseNativeFrames(buffer, &error);
        QCOMPARE(frames.size(), 1);
        QCOMPARE(frames.first().value(QStringLiteral("type")).toString(), QStringLiteral("hello"));
        QVERIFY(error.isEmpty());
        buffer += stream.right(5);
        frames = parseNativeFrames(buffer, &error);
        QCOMPARE(frames.size(), 1);
        QCOMPARE(frames.first().value(QStringLiteral("type")).toString(), QStringLiteral("list"));
        QVERIFY(buffer.isEmpty());
    }

    void oversizedFrameIsRejected() {
        QByteArray buffer(4, '\0');
        buffer[0] = static_cast<char>(0xFF);
        buffer[1] = static_cast<char>(0xFF);
        buffer[2] = static_cast<char>(0xFF);
        buffer[3] = static_cast<char>(0x7F);
        QString error;
        QVERIFY(parseNativeFrames(buffer, &error).isEmpty());
        QVERIFY(!error.isEmpty());
        QVERIFY(buffer.isEmpty());
    }

    void companionIdMatchesManifestKey() {
        QFile f(testutil::fixturesDir() + QStringLiteral("/../companion/manifest.json"));
        QVERIFY(f.open(QIODevice::ReadOnly));
        const QJsonObject manifest = QJsonDocument::fromJson(f.readAll()).object();
        const QString id = extensionIdFromManifestKey(manifest.value(QStringLiteral("key")).toString());
        QFile expected(testutil::fixturesDir() + QStringLiteral("/../companion/EXTENSION_ID"));
        QVERIFY(expected.open(QIODevice::ReadOnly));
        QCOMPARE(id, QString::fromLatin1(expected.readAll()).trimmed());
        QVERIFY(isValidExtensionId(id));
        QVERIFY(manifest.value(QStringLiteral("permissions")).toArray().contains(QStringLiteral("management")));
    }

    void nativeHostLaunchDetection() {
        QVERIFY(launchedAsNativeHost({QStringLiteral("chrome-extension://abc/")}));
        QVERIFY(!launchedAsNativeHost({QStringLiteral("scan")}));
        QVERIFY(!launchedAsNativeHost({}));
    }

    void registersHostManifestsInUserDataDirs() {
        QTemporaryDir tmp;
        const QString udd = tmp.path() + QStringLiteral("/Chrome");
        QDir().mkpath(udd);
        const QList<HostRegistration> regs = registerNativeHost(QStringLiteral("/opt/extwatch/extwatch"), tmp.path(),
                                                                {{BrowserKind::Chrome, QStringLiteral("Chrome"), udd},
                                                                 {BrowserKind::Brave, QStringLiteral("Brave"), tmp.path() + QStringLiteral("/missing")}});
        QCOMPARE(regs.size(), 2);
#ifndef Q_OS_WIN
        QVERIFY(regs.first().ok);
        QFile manifest(udd + QStringLiteral("/NativeMessagingHosts/app.extwatch.host.json"));
        QVERIFY(manifest.open(QIODevice::ReadOnly));
        const QJsonObject m = QJsonDocument::fromJson(manifest.readAll()).object();
        QCOMPARE(m.value(QStringLiteral("name")).toString(), QStringLiteral("app.extwatch.host"));
        QCOMPARE(m.value(QStringLiteral("type")).toString(), QStringLiteral("stdio"));
        QCOMPARE(m.value(QStringLiteral("path")).toString(), QStringLiteral("/opt/extwatch/extwatch"));
        QVERIFY(m.value(QStringLiteral("allowed_origins")).toArray().first().toString().startsWith(QStringLiteral("chrome-extension://")));
        QVERIFY(!regs.last().ok);  // missing browser dir
        const QList<HostRegistration> gone = unregisterNativeHost({{BrowserKind::Chrome, QStringLiteral("Chrome"), udd}});
        QVERIFY(gone.first().ok);
        QVERIFY(!QFile::exists(udd + QStringLiteral("/NativeMessagingHosts/app.extwatch.host.json")));
#endif
    }
};

QTEST_GUILESS_MAIN(TestNativeMessaging)
#include "test_nativemessaging.moc"
