#include "core/chrometime.h"

#include <QTimeZone>

namespace extwatch {

QDateTime chromeTimeToDateTime(qint64 microsecondsSince1601) {
    const qint64 unixMillis =
        microsecondsSince1601 / 1000 - kWindowsToUnixEpochSeconds * 1000;
    return QDateTime::fromMSecsSinceEpoch(unixMillis, QTimeZone::UTC);
}

qint64 dateTimeToChromeTime(const QDateTime& dt) {
    return (dt.toMSecsSinceEpoch() + kWindowsToUnixEpochSeconds * 1000) * 1000;
}

std::optional<qint64> parseChromeTime(const QJsonValue& value) {
    if (value.isString()) {
        bool ok = false;
        const qint64 n = value.toString().toLongLong(&ok);
        if (ok && n > 0) {
            return n;
        }
        return std::nullopt;
    }
    if (value.isDouble()) {
        const double d = value.toDouble();
        if (d > 0) {
            return static_cast<qint64>(d);
        }
    }
    return std::nullopt;
}

}  // namespace extwatch
