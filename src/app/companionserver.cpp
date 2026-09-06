#include "app/companionserver.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QLocalSocket>
#include <QTimer>

#include "core/companion.h"

namespace extwatch {

CompanionServer::CompanionServer(QObject* parent) : QObject(parent) {
    connect(&m_server, &QLocalServer::newConnection, this, &CompanionServer::onNewConnection);
}

CompanionServer::~CompanionServer() {
    for (Connection* c : m_connections) {
        c->socket->disconnect(this);
        c->socket->abort();
        delete c;
    }
    m_connections.clear();
    m_server.close();
}

bool CompanionServer::start(QString* error) {
    const QString name = ipcServerName();
    QLocalServer::removeServer(name);
    m_server.setSocketOptions(QLocalServer::UserAccessOption);
    if (!m_server.listen(name)) {
        if (error) *error = m_server.errorString();
        return false;
    }
    return true;
}

QStringList CompanionServer::connectedBrowsers() const {
    QStringList out;
    for (const Connection* c : m_connections) {
        if (!c->browser.isEmpty() && !out.contains(c->browser)) {
            out.append(c->browser);
        }
    }
    return out;
}

QStringList CompanionServer::browsersWith(const QString& extId) const {
    QStringList out;
    for (const Connection* c : m_connections) {
        if (c->extensionIds.contains(extId) && !out.contains(c->browser)) {
            out.append(c->browser);
        }
    }
    return out;
}

void CompanionServer::onNewConnection() {
    while (QLocalSocket* socket = m_server.nextPendingConnection()) {
        auto* c = new Connection;
        c->socket = socket;
        m_connections.append(c);
        connect(socket, &QLocalSocket::readyRead, this, [this, c]() { onReadyRead(c); });
        connect(socket, &QLocalSocket::disconnected, this, [this, c]() { onDisconnected(c); });
        // Ask for the inventory right away.
        QJsonObject list;
        list.insert(QStringLiteral("type"), QStringLiteral("list"));
        list.insert(QStringLiteral("id"), 0);
        send(c, list);
    }
    emit connectionsChanged();
}

void CompanionServer::onDisconnected(Connection* c) {
    m_connections.removeAll(c);
    for (auto it = m_pending.begin(); it != m_pending.end(); ++it) {
        if (it->waiting.remove(c->socket) && it->waiting.isEmpty()) {
            QTimer::singleShot(0, this, [this, id = it.key()]() { finish(id); });
        }
    }
    c->socket->deleteLater();
    delete c;
    emit connectionsChanged();
}

void CompanionServer::onReadyRead(Connection* c) {
    c->buffer += c->socket->readAll();
    while (true) {
        const qsizetype nl = c->buffer.indexOf('\n');
        if (nl < 0) {
            break;
        }
        const QByteArray line = c->buffer.left(nl);
        c->buffer.remove(0, nl + 1);
        const QJsonObject envelope = QJsonDocument::fromJson(line).object();
        if (envelope.value(QStringLiteral("channel")).toString() == QStringLiteral("companion")) {
            handle(c, envelope.value(QStringLiteral("message")).toObject());
        }
    }
}

void CompanionServer::send(Connection* c, const QJsonObject& message) {
    QJsonObject envelope;
    envelope.insert(QStringLiteral("message"), message);
    c->socket->write(QJsonDocument(envelope).toJson(QJsonDocument::Compact) + '\n');
}

void CompanionServer::handle(Connection* c, const QJsonObject& m) {
    const QString type = m.value(QStringLiteral("type")).toString();
    if (!m.value(QStringLiteral("browser")).toString().isEmpty()) {
        c->browser = m.value(QStringLiteral("browser")).toString();
    }
    if (type == QStringLiteral("hello")) {
        c->companionVersion = m.value(QStringLiteral("companionVersion")).toString();
        emit connectionsChanged();
    } else if (type == QStringLiteral("list")) {
        c->extensionIds.clear();
        for (const QJsonValue& v : m.value(QStringLiteral("extensions")).toArray()) {
            c->extensionIds.append(v.toObject().value(QStringLiteral("id")).toString());
        }
        emit connectionsChanged();
    } else if (type == QStringLiteral("event")) {
        const QJsonObject ext = m.value(QStringLiteral("extension")).toObject();
        const QString event = m.value(QStringLiteral("event")).toString();
        const QString id = ext.value(QStringLiteral("id")).toString();
        if (event == QStringLiteral("installed") && !c->extensionIds.contains(id)) {
            c->extensionIds.append(id);
        } else if (event == QStringLiteral("uninstalled")) {
            c->extensionIds.removeAll(id);
        }
        emit extensionEvent(c->browser, event, id, ext.value(QStringLiteral("version")).toString());
    } else if (type == QStringLiteral("result")) {
        const int id = m.value(QStringLiteral("id")).toInt(-1);
        auto it = m_pending.find(id);
        if (it == m_pending.end()) {
            return;
        }
        const QString browser = c->browser.isEmpty() ? QStringLiteral("browser") : c->browser;
        if (m.value(QStringLiteral("ok")).toBool()) {
            it->succeeded.append(browser);
        } else {
            const QString error = m.value(QStringLiteral("error")).toString();
            // "not installed" in one browser is expected when the request is broadcast.
            if (!error.contains(QStringLiteral("Failed to find"), Qt::CaseInsensitive) &&
                !error.contains(QStringLiteral("not found"), Qt::CaseInsensitive) &&
                !error.contains(QStringLiteral("No extension"), Qt::CaseInsensitive)) {
                it->failed.append(QStringLiteral("%1: %2").arg(browser, error));
            }
        }
        it->waiting.remove(c->socket);
        if (it->waiting.isEmpty()) {
            finish(id);
        }
    }
}

void CompanionServer::setEnabled(const QString& extId, bool enabled, ResultHandler done, int timeoutMs) {
    const int id = m_nextRequestId++;
    Pending p;
    p.extId = extId;
    p.done = std::move(done);
    for (Connection* c : m_connections) {
        p.waiting.insert(c->socket);
    }
    if (p.waiting.isEmpty()) {
        if (p.done) {
            p.done({}, {QStringLiteral("no companion connected")});
        }
        return;
    }
    p.timer = new QTimer(this);
    p.timer->setSingleShot(true);
    connect(p.timer, &QTimer::timeout, this, [this, id]() { finish(id); });
    p.timer->start(timeoutMs);
    m_pending.insert(id, p);
    QJsonObject request;
    request.insert(QStringLiteral("type"), QStringLiteral("setEnabled"));
    request.insert(QStringLiteral("id"), id);
    request.insert(QStringLiteral("extensionId"), extId);
    request.insert(QStringLiteral("enabled"), enabled);
    for (Connection* c : m_connections) {
        send(c, request);
    }
}

void CompanionServer::finish(int requestId) {
    auto it = m_pending.find(requestId);
    if (it == m_pending.end()) {
        return;
    }
    Pending p = *it;
    m_pending.erase(it);
    if (p.timer) {
        p.timer->stop();
        p.timer->deleteLater();
    }
    if (!p.waiting.isEmpty()) {
        p.failed.append(QStringLiteral("%1 browser(s) did not answer in time").arg(p.waiting.size()));
    }
    if (p.done) {
        p.done(p.succeeded, p.failed);
    }
}

}  // namespace extwatch
