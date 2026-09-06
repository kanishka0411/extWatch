#include "core/inventory.h"

#include <QDir>
#include <QFileInfo>
#include <QSet>
#include <QVersionNumber>
#include <algorithm>

#include "core/crxid.h"

namespace extwatch {

int compareVersions(const QString& a, const QString& b) {
    return QVersionNumber::compare(QVersionNumber::fromString(a), QVersionNumber::fromString(b));
}

QString InstalledExtension::displayName() const {
    if (const VersionDir* v = activeVersionDir(); v && !v->manifest.name.isEmpty()) {
        return v->manifest.name;
    }
    for (const VersionDir& v : versions) {
        if (!v.manifest.name.isEmpty()) {
            return v.manifest.name;
        }
    }
    if (record && !record->manifestName.isEmpty()) {
        return record->manifestName;
    }
    return id;
}

QString InstalledExtension::activeVersion() const {
    if (const VersionDir* v = activeVersionDir()) {
        return v->version;
    }
    if (record && !record->manifestVersion.isEmpty()) {
        return record->manifestVersion;
    }
    return versions.isEmpty() ? QString() : versions.first().version;
}

const VersionDir* InstalledExtension::activeVersionDir() const {
    for (const VersionDir& v : versions) {
        if (v.isActive) {
            return &v;
        }
    }
    return nullptr;
}

bool InstalledExtension::enabled() const {
    return record ? record->enabled() : false;
}

bool InstalledExtension::unpacked() const {
    return record && (record->location == static_cast<int>(InstallLocation::Unpacked) ||
                      record->hasAbsolutePath());
}

int InstalledExtension::location() const {
    return record ? record->location : 0;
}

bool isBuiltinExtensionId(const QString& id) {
    // Components that ship inside the browser but appear in the profile's extension settings.
    static const QSet<QString> builtin = {
        QStringLiteral("ahfgeienlihckogmohjhadlkjgocpleb"),  // Chrome Web Store
        QStringLiteral("mhjfbmdgcfjbbpaeojofohoefgiehjai"),  // Chrome PDF Viewer
        QStringLiteral("pkedcjkdefgpdelpbcmbmeomcjbeemfm"),  // Chrome Media Router
        QStringLiteral("nmmhkkegccagdldgiimedpiccmgmieda"),  // Google Wallet
        QStringLiteral("nkeimhogjdpnpccoofpliimaahmaaome"),  // Google Hangouts
        QStringLiteral("kmendfapggjehodndflmmgagdbamhnfd"),  // CryptoTokenExtension
        QStringLiteral("gfdkimpbcpahaombhbimeihdjnejgicl"),  // Feedback
        QStringLiteral("neajdppkdcdipfabeoofebfddakdcjhd"),  // Google Network Speech
    };
    return builtin.contains(id);
}

bool isBrowserInternalPath(const QString& path) {
    return path.contains(QStringLiteral(".app/Contents/")) || path.startsWith(QStringLiteral("/Applications/")) ||
           path.startsWith(QStringLiteral("/usr/")) || path.startsWith(QStringLiteral("/opt/")) ||
           path.startsWith(QStringLiteral("/snap/")) || path.contains(QStringLiteral("Program Files")) ||
           path.contains(QStringLiteral("/resources/"), Qt::CaseInsensitive);
}

namespace {

VersionDir readVersionDir(const QString& id, const QFileInfo& dirInfo) {
    VersionDir v;
    v.dirName = dirInfo.fileName();
    v.path = dirInfo.absoluteFilePath();
    v.manifest = readManifest(v.path);
    v.version = v.manifest.version;
    if (v.version.isEmpty()) {
        v.version = v.dirName.section(u'_', 0, 0);
    }
    v.hasWebstoreMetadata =
        QFileInfo::exists(v.path + QStringLiteral("/_metadata/verified_contents.json"));
    if (!v.manifest.key.isEmpty()) {
        v.keyMatchesId = extensionIdFromManifestKey(v.manifest.key) == id;
    }
    return v;
}

void sortVersionsNewestFirst(QList<VersionDir>& versions) {
    std::stable_sort(versions.begin(), versions.end(), [](const VersionDir& a, const VersionDir& b) {
        const int c = compareVersions(a.version, b.version);
        if (c != 0) {
            return c > 0;
        }
        return a.dirName > b.dirName;
    });
}

}  // namespace

ProfileInventory inventoryProfile(const Profile& profile) {
    ProfileInventory inv;
    inv.profile = profile;

    ProfilePrefs prefs = readProfilePrefs(profile.path);
    inv.warnings = prefs.warnings;

    const QDir extensionsDir(profile.path + QStringLiteral("/Extensions"));
    QHash<QString, InstalledExtension> byId;

    // 1. Everything the browser knows about.
    for (auto it = prefs.extensions.cbegin(); it != prefs.extensions.cend(); ++it) {
        const ExtensionRecord& rec = it.value();
        if (isBrowserInternalLocation(rec.location) || isBuiltinExtensionId(rec.id) ||
            (rec.hasAbsolutePath() && isBrowserInternalPath(rec.path))) {
            continue;
        }
        InstalledExtension ext;
        ext.id = rec.id;
        ext.record = rec;

        QString activeDirPath;
        if (rec.hasAbsolutePath()) {
            const QFileInfo fi(rec.path);
            if (fi.isDir()) {
                VersionDir v = readVersionDir(rec.id, fi);
                v.isActive = true;
                ext.versions.append(v);
            } else {
                ext.notes.append(QStringLiteral("unpacked path missing: %1").arg(rec.path));
            }
        } else if (!rec.path.isEmpty()) {
            activeDirPath = QDir::cleanPath(extensionsDir.filePath(rec.path));
        }

        if (!rec.hasAbsolutePath()) {
            const QDir idDir(extensionsDir.filePath(rec.id));
            const QFileInfoList dirs = idDir.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot);
            for (const QFileInfo& fi : dirs) {
                VersionDir v = readVersionDir(rec.id, fi);
                v.isActive = !activeDirPath.isEmpty() &&
                             QDir::cleanPath(fi.absoluteFilePath()) == activeDirPath;
                ext.versions.append(v);
            }
            if (ext.versions.isEmpty()) {
                // Brave and Chrome keep placeholder records (no path, no manifest, no files) for
                // extensions that are not actually installed in this profile. Skip those.
                if (rec.path.isEmpty() && rec.cachedManifest.isEmpty()) {
                    continue;
                }
                ext.notes.append(QStringLiteral("no files on disk"));
            } else if (!activeDirPath.isEmpty() && !ext.activeVersionDir()) {
                ext.notes.append(QStringLiteral("prefs point at a missing version directory"));
            }
        }
        sortVersionsNewestFirst(ext.versions);
        byId.insert(ext.id, ext);
    }

    // 2. Directories the browser has no record of (leftovers, or a record we could not parse).
    if (extensionsDir.exists()) {
        const QFileInfoList idDirs = extensionsDir.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot);
        for (const QFileInfo& idInfo : idDirs) {
            const QString id = idInfo.fileName();
            if (!isValidExtensionId(id) || byId.contains(id)) {
                continue;
            }
            InstalledExtension ext;
            ext.id = id;
            ext.notes.append(QStringLiteral("files on disk without a preferences entry"));
            const QFileInfoList dirs =
                QDir(idInfo.filePath()).entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot);
            for (const QFileInfo& fi : dirs) {
                ext.versions.append(readVersionDir(id, fi));
            }
            if (ext.versions.isEmpty()) {
                continue;
            }
            sortVersionsNewestFirst(ext.versions);
            byId.insert(id, ext);
        }
    }

    inv.extensions = byId.values();
    std::sort(inv.extensions.begin(), inv.extensions.end(),
              [](const InstalledExtension& a, const InstalledExtension& b) {
                  const int c = a.displayName().compare(b.displayName(), Qt::CaseInsensitive);
                  return c != 0 ? c < 0 : a.id < b.id;
              });
    return inv;
}

}  // namespace extwatch
