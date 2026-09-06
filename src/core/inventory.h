#pragma once

#include <QList>
#include <QString>
#include <QStringList>
#include <optional>

#include "core/discovery.h"
#include "core/manifest.h"
#include "core/prefs.h"

namespace extwatch {

// One <version>_<n> directory on disk.
struct VersionDir {
    QString dirName;   // "1.2.3_0"
    QString path;      // absolute
    QString version;   // from manifest.json, falls back to the dir name prefix
    ManifestFacts manifest;
    bool hasWebstoreMetadata = false;  // _metadata/verified_contents.json present
    bool keyMatchesId = true;          // manifest key derives to the directory id
    bool isActive = false;             // this is the version the prefs point at
};

struct InstalledExtension {
    QString id;
    std::optional<ExtensionRecord> record;  // missing when files exist without a prefs entry
    QList<VersionDir> versions;             // newest first
    QStringList notes;

    QString displayName() const;
    QString activeVersion() const;
    const VersionDir* activeVersionDir() const;
    bool enabled() const;
    bool unpacked() const;
    int location() const;
};

struct ProfileInventory {
    Profile profile;
    QList<InstalledExtension> extensions;  // sorted by display name
    QStringList warnings;
};

bool isBuiltinExtensionId(const QString& id);
bool isBrowserInternalPath(const QString& path);

// Compares dotted version strings the way Chrome does (numeric components).
int compareVersions(const QString& a, const QString& b);

ProfileInventory inventoryProfile(const Profile& profile);

}  // namespace extwatch
