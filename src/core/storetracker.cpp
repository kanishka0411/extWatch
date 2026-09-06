#include "core/storetracker.h"

#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QSet>
#include <QThread>

#include "core/database.h"
#include "core/rules.h"
#include "core/scanner.h"

namespace extwatch {

StoreTrackingResult runStoreTracking(const QString& dataDir, int maxFetches, qint64 minAgeSeconds,
                                     const std::function<bool()>& cancelled) {
    StoreTrackingResult result;
    Database db;
    QString error;
    if (!db.open(databasePath(dataDir), &error)) {
        result.errors.append(error);
        return result;
    }
    const qint64 now = QDateTime::currentSecsSinceEpoch();

    // Distinct store-installed extension IDs that are still present.
    QHash<QString, QList<ExtensionRow>> byExtId;
    for (const BrowserRow& b : db.browsers()) {
        for (const ProfileRow& p : db.profilesForBrowser(b.id)) {
            for (const ExtensionRow& e : db.extensionsForProfile(p.id, /*presentOnly=*/true)) {
                if (!e.fromWebstore) {
                    continue;
                }
                byExtId[e.extId].append(e);
            }
        }
    }

    QStringList ids = byExtId.keys();
    ids.sort();
    for (const QString& extId : ids) {
        if (cancelled && cancelled()) {
            break;
        }
        if (result.fetched >= maxFetches) {
            result.skipped++;
            continue;
        }
        const std::optional<StoreListing> previous = db.storeListing(extId);
        if (previous && now - previous->fetchedAt < minAgeSeconds) {
            result.skipped++;
            continue;
        }
        if (result.fetched > 0) {
            QThread::msleep(1500);  // be polite to the store
        }
        StoreListing listing = fetchStoreListing(extId);
        result.fetched++;
        if (!listing.error.isEmpty() && listing.httpStatus == 0) {
            result.errors.append(QStringLiteral("%1: %2").arg(extId, listing.error));
            continue;  // network trouble: keep the old record
        }
        const QList<ExtensionRow>& rows = byExtId.value(extId);
        const QString name = rows.isEmpty() ? extId : rows.first().name;

        auto raise = [&](const QString& kind, const char* rule, const QString& detail) {
            const Finding f = findingForRule(QString::fromLatin1(rule), detail);
            StoreEvent ev;
            ev.kind = kind;
            ev.extId = extId;
            ev.extName = name;
            ev.detail = detail;
            ev.severity = severityId(f.severity);
            for (const ExtensionRow& row : rows) {
                EventRow er;
                er.extensionId = row.id;
                er.kind = kind;
                er.toVersionId = row.currentVersionId;
                er.at = now;
                er.maxSeverity = ev.severity;
                er.findingsJson = QString::fromUtf8(QJsonDocument(findingsToJson({f})).toJson(QJsonDocument::Compact));
                const qint64 id = db.insertEvent(er);
                if (id >= 0) {
                    ev.eventRowIds.append(id);
                }
            }
            result.events.append(ev);
        };

        if (previous && previous->found) {
            if (listing.found && !listing.developer.isEmpty() && !previous->developer.isEmpty() &&
                listing.developer != previous->developer) {
                raise(QStringLiteral("publisher_changed"), "publisher.changed",
                      QStringLiteral("The Web Store listing is now offered by \"%1\" (was \"%2\").").arg(listing.developer, previous->developer));
            }
            if (!listing.found && listing.gone) {
                raise(QStringLiteral("removed_from_store"), "store.removed",
                      QStringLiteral("The Web Store listing for %1 is gone.").arg(name));
            }
        }
        db.upsertStoreListing(listing);
    }
    return result;
}

}  // namespace extwatch
