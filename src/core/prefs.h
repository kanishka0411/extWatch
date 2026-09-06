#pragma once

#include <QHash>
#include <QJsonObject>
#include <QList>
#include <QString>
#include <QStringList>
#include <optional>

namespace extwatch {

// Chromium's Manifest::Location values as stored in extensions.settings.<id>.location.
enum class InstallLocation : int {
    Invalid = 0,
    Internal = 1,               // installed by the user, usually from the Web Store
    ExternalPref = 2,
    ExternalRegistry = 3,
    Unpacked = 4,               // "Load unpacked" developer extension, absolute path
    Component = 5,              // part of the browser
    ExternalPrefDownload = 6,
    ExternalPolicyDownload = 7,
    CommandLine = 8,
    ExternalPolicy = 9,
    ExternalComponent = 10,     // part of the browser, downloaded
};

QString installLocationId(int location);
bool isBrowserInternalLocation(int location);  // Component or ExternalComponent
QString disableReasonName(int reason);

struct PermissionSet {
    bool present = false;
    QStringList api;
    QStringList explicitHosts;
    QStringList scriptableHosts;
    QStringList manifestPermissions;
};

// One entry of extensions.settings in Secure Preferences (or Preferences).
struct ExtensionRecord {
    QString id;
    QString path;  // "<id>/<version>_<n>" relative to Extensions/, or absolute for unpacked
    int location = 0;
    std::optional<int> state;        // legacy field: 1 enabled, 0 disabled
    bool disableReasonsPresent = false;
    QList<int> disableReasons;       // bit values, from either the bitmask or the list form
    bool fromWebstore = false;
    bool wasInstalledByDefault = false;
    std::optional<qint64> firstInstallTime;  // Chrome microseconds
    std::optional<qint64> lastUpdateTime;
    QJsonObject cachedManifest;
    QString manifestName;
    QString manifestVersion;
    QString updateUrl;
    PermissionSet activePermissions;
    PermissionSet grantedPermissions;

    bool enabled() const;
    QStringList disableReasonNames() const;
    bool hasAbsolutePath() const;
};

struct ProfilePrefs {
    QHash<QString, ExtensionRecord> extensions;
    QStringList warnings;
};

ExtensionRecord parseExtensionRecord(const QString& id, const QJsonObject& object);

// Reads "Secure Preferences" and "Preferences" from a profile directory. Secure Preferences wins
// when both contain an entry for the same id.
ProfilePrefs readProfilePrefs(const QString& profileDir);

}  // namespace extwatch
