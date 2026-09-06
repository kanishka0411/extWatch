#pragma once

#include <QList>
#include <QString>
#include <functional>

#include "core/storemeta.h"

namespace extwatch {

struct StoreEvent {
    QString kind;  // publisher_changed, removed_from_store, store_version_ahead
    QString extId;
    QString extName;
    QString detail;
    QString severity;
    QList<qint64> eventRowIds;
};

struct StoreTrackingResult {
    int fetched = 0;
    int skipped = 0;
    QList<StoreEvent> events;
    QStringList errors;
};

// Fetches Web Store listings for the store-installed extensions in the archive whose listing is
// older than `minAgeSeconds`, records them, and raises events when the publisher changes or the
// listing disappears. Blocking; meant for a worker thread. Opt-in only.
StoreTrackingResult runStoreTracking(const QString& dataDir, int maxFetches = 40,
                                     qint64 minAgeSeconds = 24 * 3600,
                                     const std::function<bool()>& cancelled = {});

}  // namespace extwatch
