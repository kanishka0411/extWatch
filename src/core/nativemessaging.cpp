#include "core/nativemessaging.h"

#include <QJsonDocument>
#include <QtEndian>

namespace extwatch {

namespace {
constexpr qint64 kMaxFrame = 1024 * 1024;
}

QByteArray frameNativeMessage(const QJsonObject& message) {
    const QByteArray json = QJsonDocument(message).toJson(QJsonDocument::Compact);
    QByteArray out(4, '\0');
    qToLittleEndian<quint32>(static_cast<quint32>(json.size()), out.data());
    out += json;
    return out;
}

QList<QJsonObject> parseNativeFrames(QByteArray& buffer, QString* error) {
    QList<QJsonObject> out;
    while (buffer.size() >= 4) {
        const quint32 length = qFromLittleEndian<quint32>(buffer.constData());
        if (length > kMaxFrame) {
            if (error) {
                *error = QStringLiteral("frame of %1 bytes exceeds the native messaging limit").arg(length);
            }
            buffer.clear();
            return out;
        }
        if (buffer.size() < 4 + static_cast<qsizetype>(length)) {
            break;
        }
        const QJsonDocument doc = QJsonDocument::fromJson(buffer.mid(4, static_cast<qsizetype>(length)));
        buffer.remove(0, 4 + static_cast<qsizetype>(length));
        if (doc.isObject()) {
            out.append(doc.object());
        } else if (error) {
            *error = QStringLiteral("frame is not a JSON object");
        }
    }
    return out;
}

}  // namespace extwatch
