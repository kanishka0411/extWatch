#pragma once

#include <QJsonObject>
#include <QString>
#include <QUrl>

namespace extwatch {

// What the Chrome Web Store listing page says about an extension. Fetching is opt-in: it sends
// the extension ID to Google.
struct StoreListing {
    QString extId;
    int httpStatus = 0;
    bool found = false;
    bool gone = false;  // 404, or redirected to the generic store page: the listing does not exist
    QString name;
    QString developer;       // "Offered by"
    QString developerEmail;
    QString version;
    QString updated;         // as displayed, e.g. "September 1, 2026"
    QString size;
    QString rating;
    QString users;
    QString traderStatus;    // "trader", "non-trader" or empty
    QString error;
    qint64 fetchedAt = 0;

    QJsonObject toJson() const;
    static StoreListing fromJson(const QJsonObject& o);
};

QUrl storeListingUrl(const QString& extId);
StoreListing parseStoreListing(const QString& extId, const QByteArray& html, int httpStatus);

// Blocking fetch (spins a local event loop; safe on worker threads).
StoreListing fetchStoreListing(const QString& extId, int timeoutMs = 20000);

// Omaha update check: the version the store currently serves.
struct UpdateCheck {
    bool ok = false;
    QString version;
    QString error;
};
UpdateCheck fetchUpdateCheck(const QString& extId, int timeoutMs = 20000);

}  // namespace extwatch
