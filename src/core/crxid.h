#pragma once

#include <QByteArray>
#include <QString>
#include <QStringView>

namespace extwatch {

// Chrome extension IDs are the first 128 bits of SHA-256 over the DER-encoded public key,
// written as 32 characters in the range a-p (one per nibble).
QString extensionIdFromPublicKey(const QByteArray& derPublicKey);

// Same, from the base64 "key" field Chrome writes into every unpacked manifest.json.
QString extensionIdFromManifestKey(const QString& base64Key);

bool isValidExtensionId(QStringView id);

}  // namespace extwatch
