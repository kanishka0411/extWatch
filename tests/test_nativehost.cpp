#include <QJsonDocument>
#include <QLocalServer>
#include <QLocalSocket>
#include <QProcess>
#include <QtTest>

#include "core/companion.h"
#include "core/nativemessaging.h"

using namespace extwatch;

// Drives the real binary in native-host mode: this test plays both the browser (stdin/stdout
// frames) and the ExtWatch app (local socket server).
class TestNativeHost : public QObject {
    Q_OBJECT
private slots:
    void relaysBothWays() {
        qputenv("USER", "extwatch-test");  // isolates the IPC socket name
        QLocalServer server;
        QLocalServer::removeServer(ipcServerName());
        QVERIFY2(server.listen(ipcServerName()), qPrintable(server.errorString()));

        QProcess host;
        host.setProgram(QStringLiteral(EXTWATCH_BINARY));
        host.setArguments({QStringLiteral("chrome-extension://%1/").arg(companionExtensionId().isEmpty() ? QStringLiteral("test") : companionExtensionId())});
        host.setProcessChannelMode(QProcess::SeparateChannels);
        host.start();
        QVERIFY2(host.waitForStarted(5000), qPrintable(host.errorString()));

        // Browser -> host -> app
        QJsonObject hello;
        hello.insert(QStringLiteral("type"), QStringLiteral("hello"));
        hello.insert(QStringLiteral("browser"), QStringLiteral("chrome"));
        host.write(frameNativeMessage(hello));
        QVERIFY(host.waitForBytesWritten(3000));

        QVERIFY(server.waitForNewConnection(8000));
        QLocalSocket* app = server.nextPendingConnection();
        QVERIFY(app);
        QByteArray line;
        QTRY_VERIFY_WITH_TIMEOUT((app->waitForReadyRead(200), line += app->readAll(), line.contains('\n')), 8000);
        const QJsonObject envelope = QJsonDocument::fromJson(line.left(line.indexOf('\n'))).object();
        QCOMPARE(envelope.value(QStringLiteral("channel")).toString(), QStringLiteral("companion"));
        QVERIFY(envelope.value(QStringLiteral("origin")).toString().startsWith(QStringLiteral("chrome-extension://")));
        QCOMPARE(envelope.value(QStringLiteral("message")).toObject().value(QStringLiteral("type")).toString(), QStringLiteral("hello"));

        // App -> host -> browser
        QJsonObject request;
        request.insert(QStringLiteral("type"), QStringLiteral("setEnabled"));
        request.insert(QStringLiteral("id"), 7);
        request.insert(QStringLiteral("extensionId"), QStringLiteral("abcdefghijklmnopabcdefghijklmnop"));
        request.insert(QStringLiteral("enabled"), false);
        QJsonObject wrapper;
        wrapper.insert(QStringLiteral("message"), request);
        app->write(QJsonDocument(wrapper).toJson(QJsonDocument::Compact) + '\n');
        QVERIFY(app->waitForBytesWritten(3000));
        QByteArray out;
        QList<QJsonObject> frames;
        for (int attempt = 0; attempt < 40 && frames.isEmpty(); ++attempt) {
            host.waitForReadyRead(200);
            out += host.readAllStandardOutput();
            frames = parseNativeFrames(out);
            QCoreApplication::processEvents();
        }
        if (frames.isEmpty()) {
            qWarning() << "host state" << host.state() << "exit" << host.exitCode() << "stdout bytes" << out.size()
                       << "app socket" << app->state() << "toWrite" << app->bytesToWrite()
                       << "stderr:" << host.readAllStandardError();
        }
        QVERIFY(!frames.isEmpty());
        QCOMPARE(frames.first().value(QStringLiteral("type")).toString(), QStringLiteral("setEnabled"));
        QCOMPARE(frames.first().value(QStringLiteral("id")).toInt(), 7);

        // Ping is answered by the host itself.
        QJsonObject ping;
        ping.insert(QStringLiteral("type"), QStringLiteral("ping"));
        ping.insert(QStringLiteral("id"), 3);
        host.write(frameNativeMessage(ping));
        QVERIFY(host.waitForBytesWritten(3000));
        out.clear();
        frames.clear();
        for (int attempt = 0; attempt < 40 && frames.isEmpty(); ++attempt) {
            host.waitForReadyRead(200);
            out += host.readAllStandardOutput();
            frames = parseNativeFrames(out);
            QCoreApplication::processEvents();
        }
        if (frames.isEmpty()) {
            qWarning() << "ping stage: host state" << host.state() << "stdout bytes" << out.size()
                       << "stderr:" << host.readAllStandardError();
        }
        QVERIFY(!frames.isEmpty());
        QCOMPARE(frames.first().value(QStringLiteral("type")).toString(), QStringLiteral("pong"));

        // Closing stdin ends the host.
        host.closeWriteChannel();
        QVERIFY(host.waitForFinished(8000));
        QCOMPARE(host.exitCode(), 0);
    }
};

QTEST_GUILESS_MAIN(TestNativeHost)
#include "test_nativehost.moc"
