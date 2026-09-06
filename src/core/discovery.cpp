#include "core/discovery.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSet>
#include <algorithm>

namespace extwatch {

namespace {

bool looksLikeProfile(const QDir& dir) {
    return (dir.exists(QStringLiteral("Secure Preferences")) ||
            dir.exists(QStringLiteral("Preferences"))) &&
           dir.exists(QStringLiteral("Extensions"));
}

}  // namespace

QList<Profile> discoverProfiles(const QString& userDataDir) {
    QList<Profile> out;
    QSet<QString> seen;
    const QDir udd(userDataDir);

    QFile localState(udd.filePath(QStringLiteral("Local State")));
    if (localState.open(QIODevice::ReadOnly)) {
        const QJsonObject root = QJsonDocument::fromJson(localState.readAll()).object();
        const QJsonObject cache = root.value(QStringLiteral("profile"))
                                      .toObject()
                                      .value(QStringLiteral("info_cache"))
                                      .toObject();
        for (auto it = cache.begin(); it != cache.end(); ++it) {
            const QString dirName = it.key();
            if (dirName.contains(u'/') || dirName.contains(u'\\') || !udd.exists(dirName)) {
                continue;
            }
            const QString name = it.value().toObject().value(QStringLiteral("name")).toString();
            out.append({dirName, name.isEmpty() ? dirName : name, udd.filePath(dirName)});
            seen.insert(dirName);
        }
    }

    const QFileInfoList subdirs = udd.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);
    for (const QFileInfo& fi : subdirs) {
        const QString dirName = fi.fileName();
        if (seen.contains(dirName) || dirName == QStringLiteral("System Profile") ||
            dirName == QStringLiteral("Guest Profile")) {
            continue;
        }
        if (looksLikeProfile(QDir(fi.filePath()))) {
            out.append({dirName, dirName, fi.filePath()});
            seen.insert(dirName);
        }
    }

    // Opera-style layout: the user data directory is itself the profile.
    if (out.isEmpty() && looksLikeProfile(udd)) {
        out.append({QStringLiteral("."), QStringLiteral("Default"), udd.absolutePath()});
    }

    std::sort(out.begin(), out.end(),
              [](const Profile& a, const Profile& b) { return a.dirName < b.dirName; });
    return out;
}

QList<DiscoveredBrowser> discoverBrowsers(const QList<BrowserInstall>& candidates) {
    QList<DiscoveredBrowser> out;
    QSet<QString> seenDirs;
    for (const BrowserInstall& c : candidates) {
        const QString clean = QDir::cleanPath(c.userDataDir);
        if (seenDirs.contains(clean) || !QFileInfo(clean).isDir()) {
            continue;
        }
        QList<Profile> profiles = discoverProfiles(clean);
        if (profiles.isEmpty()) {
            continue;
        }
        seenDirs.insert(clean);
        BrowserInstall install = c;
        install.userDataDir = clean;
        out.append({install, std::move(profiles)});
    }
    return out;
}

}  // namespace extwatch
