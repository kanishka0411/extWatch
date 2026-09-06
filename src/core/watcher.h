#pragma once

#include <QFileSystemWatcher>
#include <QObject>
#include <QSet>
#include <QStringList>
#include <QTimer>

namespace extwatch {

// Watches profile directories for extension changes: new or removed version directories under
// Extensions/<id>/ and rewrites of Secure Preferences. Events are debounced and re-armed after
// each burst because browsers replace files by rename, which drops the underlying watch.
class ProfileWatcher : public QObject {
    Q_OBJECT
public:
    explicit ProfileWatcher(QObject* parent = nullptr);

    void setProfiles(const QStringList& profilePaths);
    QStringList profiles() const { return m_profiles; }
    void setDebounceMs(int ms) { m_debounce.setInterval(ms); }
    int watchedPathCount() const;

signals:
    // Emitted once per burst of file-system activity, with the paths that reported changes.
    void changed(const QStringList& paths);

private:
    void onPathChanged(const QString& path);
    void rearm();

    QFileSystemWatcher m_fs;
    QTimer m_debounce;
    QStringList m_profiles;
    QSet<QString> m_pending;
};

}  // namespace extwatch
