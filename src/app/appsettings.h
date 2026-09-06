#pragma once

#include <QStringList>

namespace extwatch {

// Thin QSettings wrapper for the tray app.
class AppSettings {
public:
    static int notifyThreshold();  // 0 everything, 1 low+, 2 medium+, 3 high only
    static void setNotifyThreshold(int level);
    static int rescanIntervalMinutes();
    static void setRescanIntervalMinutes(int minutes);
    static QStringList extraUserDataDirs();  // "kind=path" entries
    static void setExtraUserDataDirs(const QStringList& dirs);
    static bool trackPublisher();
    static void setTrackPublisher(bool on);
    static bool firstRunDone();
    static void setFirstRunDone(bool done);
};

}  // namespace extwatch
