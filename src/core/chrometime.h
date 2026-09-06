#pragma once

#include <QDateTime>
#include <QJsonValue>
#include <optional>

namespace extwatch {

// Chromium stores times as microseconds since 1601-01-01 00:00:00 UTC (the Windows epoch).
constexpr qint64 kWindowsToUnixEpochSeconds = 11644473600LL;

QDateTime chromeTimeToDateTime(qint64 microsecondsSince1601);
qint64 dateTimeToChromeTime(const QDateTime& dt);

// Accepts the string form Chrome writes ("13335348994280795") or a number. Zero and negative
// values are treated as missing.
std::optional<qint64> parseChromeTime(const QJsonValue& value);

}  // namespace extwatch
