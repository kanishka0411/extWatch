#include "core/prefs.h"

#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonParseError>

#include "core/chrometime.h"
#include "core/crxid.h"
#include "core/jsonutil.h"

namespace extwatch {

QString installLocationId(int location) {
    switch (static_cast<InstallLocation>(location)) {
        case InstallLocation::Invalid: return QStringLiteral("invalid");
        case InstallLocation::Internal: return QStringLiteral("internal");
        case InstallLocation::ExternalPref: return QStringLiteral("external_pref");
        case InstallLocation::ExternalRegistry: return QStringLiteral("external_registry");
        case InstallLocation::Unpacked: return QStringLiteral("unpacked");
        case InstallLocation::Component: return QStringLiteral("component");
        case InstallLocation::ExternalPrefDownload: return QStringLiteral("external_pref_download");
        case InstallLocation::ExternalPolicyDownload:
            return QStringLiteral("external_policy_download");
        case InstallLocation::CommandLine: return QStringLiteral("command_line");
        case InstallLocation::ExternalPolicy: return QStringLiteral("external_policy");
        case InstallLocation::ExternalComponent: return QStringLiteral("external_component");
    }
    return QStringLiteral("unknown_%1").arg(location);
}

bool isBrowserInternalLocation(int location) {
    return location == static_cast<int>(InstallLocation::Component) ||
           location == static_cast<int>(InstallLocation::ExternalComponent);
}

QString disableReasonName(int reason) {
    // extensions/browser/disable_reason.h (bit values).
    switch (reason) {
        case 1 << 0: return QStringLiteral("user_action");
        case 1 << 1: return QStringLiteral("permissions_increase");
        case 1 << 2: return QStringLiteral("reload");
        case 1 << 3: return QStringLiteral("unsupported_requirement");
        case 1 << 4: return QStringLiteral("sideload_wipeout");
        case 1 << 5: return QStringLiteral("unknown_from_sync");
        case 1 << 8: return QStringLiteral("not_verified");
        case 1 << 9: return QStringLiteral("greylist");
        case 1 << 10: return QStringLiteral("corrupted");
        case 1 << 11: return QStringLiteral("remote_install");
        case 1 << 13: return QStringLiteral("external_extension");
        case 1 << 14: return QStringLiteral("update_required_by_policy");
        case 1 << 15: return QStringLiteral("custodian_approval_required");
        case 1 << 16: return QStringLiteral("blocked_by_policy");
        case 1 << 17: return QStringLiteral("reinstall");
        case 1 << 18: return QStringLiteral("not_allowlisted");
        case 1 << 21: return QStringLiteral("unsupported_manifest_version");
        default: return QStringLiteral("reason_%1").arg(reason);
    }
}

bool ExtensionRecord::enabled() const {
    if (disableReasonsPresent) {
        return disableReasons.isEmpty();
    }
    if (state.has_value()) {
        return *state == 1;
    }
    return true;
}

QStringList ExtensionRecord::disableReasonNames() const {
    QStringList out;
    for (const int r : disableReasons) {
        out.append(disableReasonName(r));
    }
    return out;
}

bool ExtensionRecord::hasAbsolutePath() const {
    return !path.isEmpty() && QDir::isAbsolutePath(path);
}

namespace {

PermissionSet parsePermissionSet(const QJsonValue& value) {
    PermissionSet set;
    if (!value.isObject()) {
        return set;
    }
    const QJsonObject o = value.toObject();
    set.present = true;
    set.api = toStringList(o.value(QStringLiteral("api")));
    set.explicitHosts = toStringList(o.value(QStringLiteral("explicit_host")));
    set.scriptableHosts = toStringList(o.value(QStringLiteral("scriptable_host")));
    set.manifestPermissions = toStringList(o.value(QStringLiteral("manifest_permissions")));
    return set;
}

QJsonObject readJsonObjectFile(const QString& path, QString* error) {
    QFile f(path);
    if (!f.exists()) {
        return {};
    }
    if (!f.open(QIODevice::ReadOnly)) {
        if (error) {
            *error = QStringLiteral("cannot open %1: %2").arg(path, f.errorString());
        }
        return {};
    }
    QJsonParseError parseError;
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError) {
        if (error) {
            *error = QStringLiteral("cannot parse %1: %2").arg(path, parseError.errorString());
        }
        return {};
    }
    return doc.object();
}

}  // namespace

ExtensionRecord parseExtensionRecord(const QString& id, const QJsonObject& o) {
    ExtensionRecord r;
    r.id = id;
    // Windows profiles store relative paths with backslashes; ids and version dirs never contain
    // backslashes, so a blanket replacement is safe on every platform.
    r.path = o.value(QStringLiteral("path")).toString().replace(u'\\', u'/');
    r.location = o.value(QStringLiteral("location")).toInt(0);
    if (o.contains(QStringLiteral("state"))) {
        r.state = o.value(QStringLiteral("state")).toInt();
    }
    const QJsonValue dr = o.value(QStringLiteral("disable_reasons"));
    if (dr.isArray()) {
        r.disableReasonsPresent = true;
        for (const QJsonValue& v : dr.toArray()) {
            if (v.isDouble()) {
                r.disableReasons.append(v.toInt());
            }
        }
    } else if (dr.isDouble()) {
        r.disableReasonsPresent = true;
        const qint64 mask = dr.toInteger();
        for (int bit = 0; bit < 31; ++bit) {
            if (mask & (qint64{1} << bit)) {
                r.disableReasons.append(1 << bit);
            }
        }
    }
    r.fromWebstore = o.value(QStringLiteral("from_webstore")).toBool(false);
    r.wasInstalledByDefault = o.value(QStringLiteral("was_installed_by_default")).toBool(false);
    r.firstInstallTime = parseChromeTime(o.value(QStringLiteral("first_install_time")));
    if (!r.firstInstallTime) {
        r.firstInstallTime = parseChromeTime(o.value(QStringLiteral("install_time")));
    }
    r.lastUpdateTime = parseChromeTime(o.value(QStringLiteral("last_update_time")));
    r.cachedManifest = o.value(QStringLiteral("manifest")).toObject();
    r.manifestName = r.cachedManifest.value(QStringLiteral("name")).toString();
    r.manifestVersion = r.cachedManifest.value(QStringLiteral("version")).toString();
    r.updateUrl = r.cachedManifest.value(QStringLiteral("update_url")).toString();
    r.activePermissions = parsePermissionSet(o.value(QStringLiteral("active_permissions")));
    r.grantedPermissions = parsePermissionSet(o.value(QStringLiteral("granted_permissions")));
    return r;
}

ProfilePrefs readProfilePrefs(const QString& profileDir) {
    ProfilePrefs out;
    const QDir dir(profileDir);
    const QStringList files = {QStringLiteral("Secure Preferences"), QStringLiteral("Preferences")};
    for (const QString& file : files) {
        QString error;
        const QJsonObject root = readJsonObjectFile(dir.filePath(file), &error);
        if (!error.isEmpty()) {
            out.warnings.append(error);
            continue;
        }
        const QJsonObject settings = root.value(QStringLiteral("extensions"))
                                         .toObject()
                                         .value(QStringLiteral("settings"))
                                         .toObject();
        for (auto it = settings.begin(); it != settings.end(); ++it) {
            if (!isValidExtensionId(it.key()) || out.extensions.contains(it.key()) ||
                !it.value().isObject()) {
                continue;
            }
            out.extensions.insert(it.key(), parseExtensionRecord(it.key(), it.value().toObject()));
        }
    }
    return out;
}

}  // namespace extwatch
