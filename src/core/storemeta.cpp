#include "core/storemeta.h"

#include <QDateTime>
#include <QEventLoop>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QTextDocumentFragment>
#include <QTimer>

namespace extwatch {

namespace {

const char* const kUserAgent =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0.0.0 Safari/537.36";

QString unescape(const QString& s) {
    return QTextDocumentFragment::fromHtml(s).toPlainText().trimmed();
}

// Value that follows a "<div ...>Label</div><div ...>" pair in the details list.
QString labelledValue(const QString& html, const QString& label) {
    const QRegularExpression re(QStringLiteral(">%1</div>\\s*<div[^>]*>(.*?)</div>").arg(QRegularExpression::escape(label)),
                                QRegularExpression::DotMatchesEverythingOption);
    const QRegularExpressionMatch m = re.match(html);
    if (!m.hasMatch()) {
        return {};
    }
    QString value = m.captured(1);
    value.remove(QRegularExpression(QStringLiteral("<[^>]*>")));
    return unescape(value);
}

QByteArray blockingGet(const QUrl& url, int timeoutMs, int* status, QString* error, QUrl* finalUrl = nullptr) {
    QNetworkAccessManager manager;
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::UserAgentHeader, QString::fromLatin1(kUserAgent));
    request.setRawHeader("Accept-Language", "en-US,en;q=0.9");
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
    QNetworkReply* reply = manager.get(request);
    QEventLoop loop;
    QTimer timer;
    timer.setSingleShot(true);
    QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    timer.start(timeoutMs);
    loop.exec();
    QByteArray body;
    if (!reply->isFinished()) {
        reply->abort();
        if (error) *error = QStringLiteral("timeout");
    } else {
        *status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (finalUrl) {
            *finalUrl = reply->url();
        }
        body = reply->readAll();
        if (reply->error() != QNetworkReply::NoError && *status == 0 && error) {
            *error = reply->errorString();
        }
    }
    reply->deleteLater();
    return body;
}

}  // namespace

QUrl storeListingUrl(const QString& extId) {
    return QUrl(QStringLiteral("https://chromewebstore.google.com/detail/") + extId);
}

StoreListing parseStoreListing(const QString& extId, const QByteArray& body, int httpStatus) {
    StoreListing l;
    l.extId = extId;
    l.httpStatus = httpStatus;
    l.parserVersion = kStoreParserVersion;
    l.fetchedAt = QDateTime::currentSecsSinceEpoch();
    const QString html = QString::fromUtf8(body);
    if (httpStatus == 404 || html.isEmpty()) {
        l.found = false;
        l.gone = httpStatus == 404;
        return l;
    }
    const QRegularExpression titleRe(QStringLiteral("<meta property=\"og:title\" content=\"([^\"]*)\""));
    const QRegularExpressionMatch title = titleRe.match(html);
    if (title.hasMatch()) {
        l.name = unescape(title.captured(1));
        l.name.remove(QStringLiteral(" - Chrome Web Store"));
    }
    l.developer = labelledValue(html, QStringLiteral("Offered by"));
    l.version = labelledValue(html, QStringLiteral("Version"));
    l.updated = labelledValue(html, QStringLiteral("Updated"));
    l.size = labelledValue(html, QStringLiteral("Size"));
    if (html.contains(QStringLiteral(">Non-trader</div>"))) {
        l.traderStatus = QStringLiteral("non-trader");
    } else if (html.contains(QStringLiteral(">Trader</div>"))) {
        l.traderStatus = QStringLiteral("trader");
    }
    const QRegularExpression emailRe(QStringLiteral("Email.{0,1200}?<div[^>]*>\\s*([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,})\\s*</div>"),
                                     QRegularExpression::DotMatchesEverythingOption);
    const QRegularExpressionMatch email = emailRe.match(html);
    if (email.hasMatch()) {
        l.developerEmail = email.captured(1);
    }
    const QRegularExpression ratingRe(QStringLiteral("<span class=\"Vq0ZA\">([0-9.]+)</span>"));
    const QRegularExpressionMatch rating = ratingRe.match(html);
    if (rating.hasMatch()) {
        l.rating = rating.captured(1);
    }
    const QRegularExpression usersRe(QStringLiteral("([0-9][0-9,.]*[KM]?) users"));
    const QRegularExpressionMatch users = usersRe.match(html);
    if (users.hasMatch()) {
        l.users = users.captured(1);
    }
    l.found = !l.version.isEmpty() || !l.developer.isEmpty();
    if (!l.found) {
        // Unknown IDs are redirected to a page titled just "Chrome Web Store".
        l.gone = title.hasMatch() && l.name.trimmed() == QStringLiteral("Chrome Web Store");
        if (l.error.isEmpty()) {
            l.error = l.gone ? QStringLiteral("no listing with this ID")
                             : QStringLiteral("listing page did not contain the expected details");
        }
    }
    return l;
}

StoreListing fetchStoreListing(const QString& extId, int timeoutMs) {
    int status = 0;
    QString error;
    QUrl finalUrl;
    const QByteArray body = blockingGet(storeListingUrl(extId), timeoutMs, &status, &error, &finalUrl);
    StoreListing l = parseStoreListing(extId, body, status);
    if (!l.found && status == 200 && !finalUrl.path().contains(extId)) {
        l.gone = true;  // redirected away from the listing entirely
    }
    if (!error.isEmpty()) {
        l.error = error;
    }
    return l;
}

UpdateCheck fetchUpdateCheck(const QString& extId, int timeoutMs) {
    UpdateCheck u;
    const QUrl url(QStringLiteral("https://clients2.google.com/service/update2/crx?x=id%3D%1%26v%3D0%26uc&prodversion=130.0.0.0&acceptformat=crx3").arg(extId));
    int status = 0;
    const QByteArray body = blockingGet(url, timeoutMs, &status, &u.error);
    const QRegularExpression re(QStringLiteral("<updatecheck[^>]*\\sversion=\"([^\"]+)\""));
    const QRegularExpressionMatch m = re.match(QString::fromUtf8(body));
    if (m.hasMatch()) {
        u.ok = true;
        u.version = m.captured(1);
    } else if (u.error.isEmpty()) {
        u.error = status == 200 ? QStringLiteral("no update information (not in the store?)")
                                : QStringLiteral("HTTP %1").arg(status);
    }
    return u;
}

QJsonObject StoreListing::toJson() const {
    QJsonObject o;
    o.insert(QStringLiteral("id"), extId);
    o.insert(QStringLiteral("http_status"), httpStatus);
    o.insert(QStringLiteral("found"), found);
    o.insert(QStringLiteral("gone"), gone);
    o.insert(QStringLiteral("name"), name);
    o.insert(QStringLiteral("developer"), developer);
    o.insert(QStringLiteral("developer_email"), developerEmail);
    o.insert(QStringLiteral("version"), version);
    o.insert(QStringLiteral("updated"), updated);
    o.insert(QStringLiteral("size"), size);
    o.insert(QStringLiteral("rating"), rating);
    o.insert(QStringLiteral("users"), users);
    o.insert(QStringLiteral("trader_status"), traderStatus);
    if (!error.isEmpty()) {
        o.insert(QStringLiteral("error"), error);
    }
    o.insert(QStringLiteral("fetched_at"), QDateTime::fromSecsSinceEpoch(fetchedAt).toUTC().toString(Qt::ISODate));
    o.insert(QStringLiteral("parser_version"), parserVersion);  // the listing page is scraped; treat as a sensor, not ground truth
    return o;
}

StoreListing StoreListing::fromJson(const QJsonObject& o) {
    StoreListing l;
    l.extId = o.value(QStringLiteral("id")).toString();
    l.httpStatus = o.value(QStringLiteral("http_status")).toInt();
    l.found = o.value(QStringLiteral("found")).toBool();
    l.gone = o.value(QStringLiteral("gone")).toBool();
    l.name = o.value(QStringLiteral("name")).toString();
    l.developer = o.value(QStringLiteral("developer")).toString();
    l.developerEmail = o.value(QStringLiteral("developer_email")).toString();
    l.version = o.value(QStringLiteral("version")).toString();
    l.updated = o.value(QStringLiteral("updated")).toString();
    l.size = o.value(QStringLiteral("size")).toString();
    l.rating = o.value(QStringLiteral("rating")).toString();
    l.users = o.value(QStringLiteral("users")).toString();
    l.traderStatus = o.value(QStringLiteral("trader_status")).toString();
    l.error = o.value(QStringLiteral("error")).toString();
    l.fetchedAt = QDateTime::fromString(o.value(QStringLiteral("fetched_at")).toString(), Qt::ISODate).toSecsSinceEpoch();
    l.parserVersion = o.value(QStringLiteral("parser_version")).toInt();
    return l;
}

}  // namespace extwatch
