#pragma once

#include <QByteArray>
#include <QJsonObject>
#include <QList>
#include <QString>

namespace extwatch {

// Chrome native messaging framing: 4-byte little-endian length followed by UTF-8 JSON.
QByteArray frameNativeMessage(const QJsonObject& message);

// Extracts every complete frame from `buffer`, removing the consumed bytes. Frames larger than
// the 1 MiB browser limit are treated as an error and the buffer is cleared.
QList<QJsonObject> parseNativeFrames(QByteArray& buffer, QString* error = nullptr);

}  // namespace extwatch
