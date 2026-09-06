#pragma once

#include <QJsonObject>
#include <QJsonValue>
#include <QList>
#include <QString>
#include <QStringList>
#include <functional>
#include <optional>

namespace extwatch {

struct ContentScript {
    QStringList matches;
    QStringList excludeMatches;
    QStringList js;
    QStringList css;
    QString runAt;
    bool allFrames = false;
    bool matchAboutBlank = false;
};

struct RuleResource {
    QString id;
    QString path;
    bool enabled = true;
};

// The parts of manifest.json that matter for inventory and, later, for the behavior signature.
struct ManifestFacts {
    bool valid = false;
    QString error;

    int manifestVersion = 0;
    QString name;
    QString shortName;
    QString description;
    QString version;
    QString versionName;
    QString defaultLocale;
    QString key;
    QString updateUrl;
    QString homepageUrl;
    QString minimumChromeVersion;
    QString iconPath;  // largest icon, relative to the extension root

    QStringList permissions;          // API permissions (match patterns moved out for MV2)
    QStringList optionalPermissions;
    QStringList hostPermissions;
    QStringList optionalHostPermissions;
    QList<ContentScript> contentScripts;

    QString backgroundServiceWorker;
    QStringList backgroundScripts;
    QString backgroundPage;
    std::optional<bool> backgroundPersistent;

    bool externallyConnectablePresent = false;
    QStringList externallyConnectableMatches;
    QStringList externallyConnectableIds;

    QJsonValue webAccessibleResources;   // raw: shape differs between MV2 and MV3
    QJsonValue contentSecurityPolicy;    // raw: string (MV2) or object (MV3)
    QList<RuleResource> dnrRuleResources;
    QJsonObject oauth2;
    QString devtoolsPage;
    QJsonObject sandbox;

    QJsonObject raw;

    QJsonObject toJson() const;
};

// True for "<all_urls>" and scheme://host/path style match patterns.
bool isMatchPattern(const QString& s);

// Replaces __MSG_name__ placeholders using a Chrome messages.json object (case-insensitive keys).
QString resolveI18n(const QString& text, const QJsonObject& messages);

// Loads _locales/<locale>/messages.json, trying the default locale, its underscore/hyphen
// variant, then English fallbacks. Returns an empty object if none exists.
QJsonObject loadMessages(const QString& extensionDir, const QString& defaultLocale);

ManifestFacts parseManifest(const QJsonObject& manifest,
                            const std::function<QString(const QString&)>& i18n);

// Reads <extensionDir>/manifest.json (BOM tolerant) and resolves localized strings.
ManifestFacts readManifest(const QString& extensionDir);

}  // namespace extwatch
