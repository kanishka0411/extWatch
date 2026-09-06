#include "nativehost/nativehost.h"

#include <QCoreApplication>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalSocket>
#include <QMutex>
#include <QThread>
#include <QTimer>
#include <cstdio>

#include "core/companion.h"
#include "core/nativemessaging.h"

#ifdef Q_OS_WIN
#include <fcntl.h>
#include <io.h>
#else
#include <unistd.h>
#endif

namespace extwatch {

namespace {

// Blocking stdin reader; frames are handed to the main thread through a queued signal.
class StdinReader : public QThread {
    Q_OBJECT
public:
    using QThread::QThread;

signals:
    void frame(const QJsonObject& message);
    void closed();

protected:
    void run() override {
        QByteArray buffer;
        char chunk[65536];
        while (true) {
            // read() returns as soon as any bytes are available; fread() would wait for a full chunk.
#ifdef Q_OS_WIN
            const int n = _read(_fileno(stdin), chunk, static_cast<unsigned>(sizeof(chunk)));
#else
            const ssize_t n = ::read(0, chunk, sizeof(chunk));
#endif
            if (n <= 0) {
                break;
            }
            buffer.append(chunk, static_cast<qsizetype>(n));
            QString error;
            for (const QJsonObject& m : parseNativeFrames(buffer, &error)) {
                emit frame(m);
            }
            if (!error.isEmpty()) {
                std::fprintf(stderr, "extwatch host: %s\n", qPrintable(error));
            }
        }
        emit closed();
    }
};

class Relay : public QObject {
    Q_OBJECT
public:
    explicit Relay(QString origin) : m_origin(std::move(origin)) {
        m_socket.setServerName(ipcServerName());
        connect(&m_socket, &QLocalSocket::connected, this, &Relay::onConnected);
        connect(&m_socket, &QLocalSocket::readyRead, this, &Relay::onSocketData);
        connect(&m_socket, &QLocalSocket::disconnected, this, [this]() { m_reconnect.start(); });
        connect(&m_socket, &QLocalSocket::errorOccurred, this, [this](QLocalSocket::LocalSocketError) {
            if (m_socket.state() == QLocalSocket::UnconnectedState) {
                m_reconnect.start();
            }
        });
        m_reconnect.setInterval(5000);
        m_reconnect.setSingleShot(true);
        connect(&m_reconnect, &QTimer::timeout, this, [this]() { m_socket.connectToServer(); });
        m_socket.connectToServer();
    }

    ~Relay() override {
        // Members are destroyed in reverse order: the timer would be gone when the socket's
        // destructor emits disconnected(), so detach the signal handlers first.
        m_socket.disconnect(this);
        m_reconnect.stop();
    }

    void toBrowser(const QJsonObject& message) {
        const QByteArray frame = frameNativeMessage(message);
        QMutexLocker lock(&m_stdoutMutex);
        std::fwrite(frame.constData(), 1, static_cast<size_t>(frame.size()), stdout);
        std::fflush(stdout);
    }

public slots:
    void onBrowserFrame(const QJsonObject& message) {
        const QString type = message.value(QStringLiteral("type")).toString();
        if (type == QStringLiteral("ping")) {
            QJsonObject pong;
            pong.insert(QStringLiteral("type"), QStringLiteral("pong"));
            pong.insert(QStringLiteral("id"), message.value(QStringLiteral("id")));
            toBrowser(pong);
            return;
        }
        QJsonObject envelope;
        envelope.insert(QStringLiteral("channel"), QStringLiteral("companion"));
        envelope.insert(QStringLiteral("origin"), m_origin);
        envelope.insert(QStringLiteral("pid"), static_cast<qint64>(QCoreApplication::applicationPid()));
        envelope.insert(QStringLiteral("message"), message);
        const QByteArray line = QJsonDocument(envelope).toJson(QJsonDocument::Compact) + '\n';
        if (m_socket.state() == QLocalSocket::ConnectedState) {
            m_socket.write(line);
        } else {
            // Keep the latest hello/list so the app learns about us as soon as it starts.
            if (type == QStringLiteral("hello") || type == QStringLiteral("list")) {
                m_pending[type] = line;
            } else if (m_backlog.size() < 200) {
                m_backlog.append(line);
            }
        }
    }

private slots:
    void onConnected() {
        for (const QByteArray& line : m_pending) {
            m_socket.write(line);
        }
        for (const QByteArray& line : m_backlog) {
            m_socket.write(line);
        }
        m_backlog.clear();
    }

    void onSocketData() {
        m_buffer += m_socket.readAll();
        while (true) {
            const qsizetype nl = m_buffer.indexOf('\n');
            if (nl < 0) {
                break;
            }
            const QByteArray line = m_buffer.left(nl);
            m_buffer.remove(0, nl + 1);
            const QJsonObject envelope = QJsonDocument::fromJson(line).object();
            const QJsonObject message = envelope.value(QStringLiteral("message")).toObject();
            if (!message.isEmpty()) {
                toBrowser(message);
            }
        }
    }

private:
    QString m_origin;
    QLocalSocket m_socket;
    QTimer m_reconnect;
    QByteArray m_buffer;
    QHash<QString, QByteArray> m_pending;
    QList<QByteArray> m_backlog;
    QMutex m_stdoutMutex;
};

}  // namespace

int runNativeHost(const QStringList& args) {
#ifdef Q_OS_WIN
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    Relay relay(args.value(0));
    StdinReader reader;
    QObject::connect(&reader, &StdinReader::frame, &relay, &Relay::onBrowserFrame, Qt::QueuedConnection);
    QObject::connect(&reader, &StdinReader::closed, qApp, &QCoreApplication::quit, Qt::QueuedConnection);
    reader.start();
    const int code = QCoreApplication::exec();
    reader.wait(1000);
    return code;
}

}  // namespace extwatch

#include "nativehost.moc"
