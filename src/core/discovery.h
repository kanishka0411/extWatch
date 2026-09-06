#pragma once

#include <QList>
#include <QString>

#include "core/browserkind.h"

namespace extwatch {

struct Profile {
    QString dirName;      // "Default", "Profile 1", or "." when the user data dir is the profile
    QString displayName;  // from Local State, falls back to dirName
    QString path;         // absolute path of the profile directory
};

struct DiscoveredBrowser {
    BrowserInstall install;
    QList<Profile> profiles;
};

// Profiles inside one user data directory: Local State's profile.info_cache first, then any
// subdirectory that has preference files and an Extensions folder.
QList<Profile> discoverProfiles(const QString& userDataDir);

// Candidates that exist on disk and contain at least one profile.
QList<DiscoveredBrowser> discoverBrowsers(const QList<BrowserInstall>& candidates);

}  // namespace extwatch
