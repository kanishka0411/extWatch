#include "core/crxid.h"

#include <QCryptographicHash>

namespace extwatch {

QString extensionIdFromPublicKey(const QByteArray& derPublicKey) {
    if (derPublicKey.isEmpty()) {
        return {};
    }
    const QByteArray digest = QCryptographicHash::hash(derPublicKey, QCryptographicHash::Sha256);
    QString id;
    id.reserve(32);
    for (int i = 0; i < 16; ++i) {
        const auto byte = static_cast<unsigned char>(digest.at(i));
        id.append(QChar(static_cast<char16_t>(u'a' + (byte >> 4))));
        id.append(QChar(static_cast<char16_t>(u'a' + (byte & 0x0F))));
    }
    return id;
}

QString extensionIdFromManifestKey(const QString& base64Key) {
    const QByteArray der = QByteArray::fromBase64(base64Key.trimmed().toLatin1());
    return extensionIdFromPublicKey(der);
}

bool isValidExtensionId(QStringView id) {
    if (id.size() != 32) {
        return false;
    }
    for (const QChar c : id) {
        if (c < u'a' || c > u'p') {
            return false;
        }
    }
    return true;
}

}  // namespace extwatch
