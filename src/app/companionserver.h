#pragma once

#include <QByteArray>
#include <QHash>
#include <QJsonObject>
#include <QList>
#include <QLocalServer>
#include <QObject>
#include <QSet>
#include <QString>
#include <QStringList>
#include <functional>

class QLocalSocket;
class QTimer;

namespace extwatch {

// Accepts connections from native messaging host processes (one per browser profile that runs
// the companion extension) and multiplexes requests to them.
class CompanionServer : public QObject {
    Q_OBJECT
public:
    explicit CompanionServer(QObject* parent = nullptr);
    ~CompanionServer() override;

    bool start(QString* error = nullptr);
    int connectionCount() const { return static_cast<int>(m_connections.size()); }
    QStringList connectedBrowsers() const;
    // Browsers whose companion reports this extension as installed.
    QStringList browsersWith(const QString& extId) const;

    using ResultHandler = std::function<void(const QStringList& succeeded, const QStringList& failed)>;
    // Asks every connected companion to enable or disable the extension.
    void setEnabled(const QString& extId, bool enabled, ResultHandler done, int timeoutMs = 6000);

signals:
    void connectionsChanged();
    // installed, uninstalled, enabled, disabled
    void extensionEvent(const QString& browser, const QString& event, const QString& extId,
                        const QString& version);

private:
    struct Connection {
        QLocalSocket* socket = nullptr;
        QByteArray buffer;
        QString browser;
        QString companionVersion;
        QStringList extensionIds;
    };
    struct Pending {
        QString extId;
        QSet<QLocalSocket*> waiting;
        QStringList succeeded;
        QStringList failed;
        ResultHandler done;
        QTimer* timer = nullptr;
    };

    void onNewConnection();
    void onReadyRead(Connection* c);
    void onDisconnected(Connection* c);
    void handle(Connection* c, const QJsonObject& message);
    void send(Connection* c, const QJsonObject& message);
    void finish(int requestId);

    QLocalServer m_server;
    QList<Connection*> m_connections;
    QHash<int, Pending> m_pending;
    int m_nextRequestId = 1;
};

}  // namespace extwatch
