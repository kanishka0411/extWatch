#include "core/watcher.h"

#include <QDir>
#include <QFileInfo>

#include <QDebug>

#include "core/crxid.h"

namespace {
bool debugWatcher() {
    static const bool on = qEnvironmentVariableIsSet("EXTWATCH_DEBUG");
    return on;
}
}  // namespace

namespace extwatch {

ProfileWatcher::ProfileWatcher(QObject* parent) : QObject(parent) {
    m_debounce.setSingleShot(true);
    m_debounce.setInterval(3000);
    connect(&m_debounce, &QTimer::timeout, this, [this]() {
        const QStringList paths(m_pending.begin(), m_pending.end());
        m_pending.clear();
        rearm();
        if (debugWatcher()) {
            qInfo() << "watcher: emitting changed for" << paths;
        }
        emit changed(paths);
    });
    connect(&m_fs, &QFileSystemWatcher::directoryChanged, this, &ProfileWatcher::onPathChanged);
    connect(&m_fs, &QFileSystemWatcher::fileChanged, this, &ProfileWatcher::onPathChanged);
}

void ProfileWatcher::setProfiles(const QStringList& profilePaths) {
    m_profiles = profilePaths;
    rearm();
}

int ProfileWatcher::watchedPathCount() const {
    return static_cast<int>(m_fs.directories().size() + m_fs.files().size());
}

void ProfileWatcher::onPathChanged(const QString& path) {
    if (debugWatcher()) {
        qInfo() << "watcher: change in" << path;
    }
    m_pending.insert(path);
    m_debounce.start();
}

void ProfileWatcher::rearm() {
    QStringList wantedDirs;
    QStringList wantedFiles;
    for (const QString& profile : m_profiles) {
        const QDir extensions(profile + QStringLiteral("/Extensions"));
        if (extensions.exists()) {
            wantedDirs.append(extensions.absolutePath());
            const QFileInfoList ids = extensions.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot);
            for (const QFileInfo& id : ids) {
                if (isValidExtensionId(id.fileName())) {
                    wantedDirs.append(id.absoluteFilePath());
                }
            }
        }
        const QString prefs = profile + QStringLiteral("/Secure Preferences");
        if (QFileInfo::exists(prefs)) {
            wantedFiles.append(prefs);
        }
    }
    const QStringList currentDirs = m_fs.directories();
    const QStringList currentFiles = m_fs.files();
    QStringList stale;
    for (const QString& d : currentDirs) {
        if (!wantedDirs.contains(d)) {
            stale.append(d);
        }
    }
    for (const QString& f : currentFiles) {
        if (!wantedFiles.contains(f)) {
            stale.append(f);
        }
    }
    if (!stale.isEmpty()) {
        m_fs.removePaths(stale);
    }
    QStringList add;
    for (const QString& d : wantedDirs) {
        if (!currentDirs.contains(d)) {
            add.append(d);
        }
    }
    for (const QString& f : wantedFiles) {
        // Files are always re-added: a rename-over-write silently drops the old watch.
        if (!currentFiles.contains(f)) {
            add.append(f);
        }
    }
    if (!add.isEmpty()) {
        const QStringList failed = m_fs.addPaths(add);
        if (debugWatcher()) {
            qInfo() << "watcher: added" << add.size() - failed.size() << "paths, failed" << failed;
        }
    }
    if (debugWatcher()) {
        qInfo() << "watcher: now watching" << m_fs.directories().size() << "dirs and" << m_fs.files().size() << "files";
    }
}

}  // namespace extwatch
