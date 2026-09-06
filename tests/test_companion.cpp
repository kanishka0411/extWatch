#include <QJsonArray>
#include <QJsonDocument>
#include <QLocalSocket>
#include <QtTest>

#include "core/companion.h"
#include "core/companionserver.h"

using namespace extwatch;

namespace {

// A fake native-host relay: connects to the server and speaks the envelope protocol.
struct FakeRelay {
    QLocalSocket socket;
    QByteArray buffer;
    QString browser;
    QStringList inventory;

    bool connectAndHello(const QString& browserHint, const QStringList& ids) {
        browser = browserHint;
        inventory = ids;
        socket.connectToServer(ipcServerName());
        if (!socket.waitForConnected(3000)) {
            qWarning() << "connect to" << ipcServerName() << "failed:" << socket.errorString();
            return false;
        }
        send({{QStringLiteral("type"), QStringLiteral("hello")}, {QStringLiteral("browser"), browserHint}});
        QJsonArray exts;
        for (const QString& id : ids) exts.append(QJsonObject{{QStringLiteral("id"), id}});
        send({{QStringLiteral("type"), QStringLiteral("list")}, {QStringLiteral("browser"), browserHint}, {QStringLiteral("extensions"), exts}});
        return socket.state() == QLocalSocket::ConnectedState;
    }
    void send(const QJsonObject& message) {
        QJsonObject envelope;
        envelope.insert(QStringLiteral("channel"), QStringLiteral("companion"));
        envelope.insert(QStringLiteral("origin"), QStringLiteral("chrome-extension://%1/").arg(companionExtensionId()));
        envelope.insert(QStringLiteral("message"), message);
        socket.write(QJsonDocument(envelope).toJson(QJsonDocument::Compact) + '\n');
        socket.flush();
    }
    // Reads one request sent by the server, if any arrived.
    std::optional<QJsonObject> receive(int ms = 500) {
        socket.waitForReadyRead(ms);
        buffer += socket.readAll();
        const qsizetype nl = buffer.indexOf('\n');
        if (nl < 0) return std::nullopt;
        const QByteArray line = buffer.left(nl);
        buffer.remove(0, nl + 1);
        return QJsonDocument::fromJson(line).object().value(QStringLiteral("message")).toObject();
    }
};

}  // namespace

class TestCompanion : public QObject {
    Q_OBJECT
private slots:
    void identicalProfilesAreRefused() {
        qputenv("USER", "extwatch-companion-tie");
        CompanionServer server;
        QString error;
        QVERIFY2(server.start(&error), qPrintable(error));
        const QString ext = QStringLiteral("cjpalhdlnbpafiamejdnhcphjbkeiagm");
        FakeRelay home, work;
        QVERIFY(home.connectAndHello(QStringLiteral("chrome"), {ext, QStringLiteral("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")}));
        QVERIFY(work.connectAndHello(QStringLiteral("chrome"), {ext, QStringLiteral("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")}));
        QTRY_COMPARE_WITH_TIMEOUT(server.connectionCount(), 2, 3000);
        CompanionServer::Target target;
        target.browserKindId = QStringLiteral("chrome");
        target.extId = ext;
        target.profileExtensionIds = {ext, QStringLiteral("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")};
        QTRY_VERIFY_WITH_TIMEOUT(server.describeTarget(target).contains(QStringLiteral("same extensions")), 5000);
        bool called = false;
        QStringList reported;
        server.setEnabled(target, false, [&](const QStringList& ok, const QStringList& failed) {
            called = true;
            QVERIFY(ok.isEmpty());
            reported = failed;
        });
        QTRY_VERIFY_WITH_TIMEOUT(called, 3000);
        QVERIFY2(reported.join(u' ').contains(QStringLiteral("identical")), qPrintable(reported.join(u' ')));
        for (FakeRelay* r : {&home, &work}) {
            while (r->receive(100)) {
                // No "set" request may reach either relay.
                QVERIFY(r->buffer.isEmpty());
            }
        }
    }

    void disableTargetsOneBrowserProfile() {
        qputenv("USER", "extwatch-companion-test");
        CompanionServer server;
        QString error;
        QVERIFY2(server.start(&error), qPrintable(error));

        const QString ext = QStringLiteral("cjpalhdlnbpafiamejdnhcphjbkeiagm");
        FakeRelay chrome, brave, chromeWork;
        QVERIFY(chrome.connectAndHello(QStringLiteral("chrome"), {ext, QStringLiteral("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")}));
        QVERIFY(brave.connectAndHello(QStringLiteral("brave"), {ext}));
        QVERIFY(chromeWork.connectAndHello(QStringLiteral("chrome"), {ext, QStringLiteral("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), QStringLiteral("cccccccccccccccccccccccccccccccc")}));
        QTRY_COMPARE_WITH_TIMEOUT(server.connectionCount(), 3, 3000);
        QTRY_VERIFY_WITH_TIMEOUT(server.browsersWith(ext).size() == 2, 3000);  // chrome and brave (hints)

        // Drain the initial "list" requests the server sends on connect.
        for (FakeRelay* r : {&chrome, &brave, &chromeWork}) {
            while (r->receive(200)) {}
        }

        // Target: the Chrome "work" profile, identified by its inventory. Wait until the server
        // has processed that relay's inventory, otherwise the other Chrome profile would match.
        CompanionServer::Target target;
        target.browserKindId = QStringLiteral("chrome");
        target.extId = ext;
        target.profileExtensionIds = {ext, QStringLiteral("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), QStringLiteral("cccccccccccccccccccccccccccccccc")};
        QTRY_VERIFY_WITH_TIMEOUT(server.describeTarget(target).contains(QStringLiteral("3 extensions")), 5000);
        QStringList okBrowsers, failures;
        bool finished = false;
        server.setEnabled(target, false, [&](const QStringList& ok, const QStringList& failed) {
            okBrowsers = ok;
            failures = failed;
            finished = true;
        });
        // Only chromeWork receives the request; the others get nothing.
        std::optional<QJsonObject> req;
        QString receiver;
        for (int attempt = 0; attempt < 50 && receiver.isEmpty(); ++attempt) {
            if ((req = chromeWork.receive(50)).has_value()) receiver = QStringLiteral("chromeWork");
            else if ((req = chrome.receive(50)).has_value()) receiver = QStringLiteral("chrome");
            else if ((req = brave.receive(50)).has_value()) receiver = QStringLiteral("brave");
            QCoreApplication::processEvents();
        }
        QVERIFY2(receiver == QStringLiteral("chromeWork"), qPrintable(QStringLiteral("request went to '%1'; target described as: %2").arg(receiver, server.describeTarget(target))));
        QCOMPARE(req->value(QStringLiteral("type")).toString(), QStringLiteral("setEnabled"));
        QVERIFY(!chrome.receive(300).has_value());
        QVERIFY(!brave.receive(300).has_value());
        // Reply like the extension would.
        chromeWork.send({{QStringLiteral("type"), QStringLiteral("result")}, {QStringLiteral("id"), req->value(QStringLiteral("id"))},
                         {QStringLiteral("ok"), true}, {QStringLiteral("browser"), QStringLiteral("chrome")}});
        QTRY_VERIFY_WITH_TIMEOUT(finished, 3000);
        QCOMPARE(okBrowsers, QStringList{QStringLiteral("chrome")});
        QVERIFY(failures.isEmpty());

        // A browser with no companion is refused instead of broadcast.
        CompanionServer::Target edge;
        edge.browserKindId = QStringLiteral("edge");
        edge.extId = ext;
        bool refused = false;
        server.setEnabled(edge, false, [&](const QStringList& ok, const QStringList& failed) { refused = ok.isEmpty() && !failed.isEmpty(); });
        QVERIFY(refused);
    }
};

QTEST_GUILESS_MAIN(TestCompanion)
#include "test_companion.moc"
