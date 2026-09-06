#include "app/appsettings.h"

#include <QSettings>

namespace extwatch {

namespace {
const char* const kThreshold = "notifications/threshold";
const char* const kInterval = "scan/intervalMinutes";
const char* const kExtraDirs = "scan/extraUserDataDirs";
const char* const kFirstRun = "app/firstRunDone";
const char* const kTrackPublisher = "store/trackPublisher";
}  // namespace

int AppSettings::notifyThreshold() {
    return QSettings().value(QLatin1StringView(kThreshold), 0).toInt();
}

void AppSettings::setNotifyThreshold(int level) {
    QSettings().setValue(QLatin1StringView(kThreshold), level);
}

int AppSettings::rescanIntervalMinutes() {
    return qBound(1, QSettings().value(QLatin1StringView(kInterval), 15).toInt(), 24 * 60);
}

void AppSettings::setRescanIntervalMinutes(int minutes) {
    QSettings().setValue(QLatin1StringView(kInterval), qBound(1, minutes, 24 * 60));
}

QStringList AppSettings::extraUserDataDirs() {
    return QSettings().value(QLatin1StringView(kExtraDirs)).toStringList();
}

void AppSettings::setExtraUserDataDirs(const QStringList& dirs) {
    QSettings().setValue(QLatin1StringView(kExtraDirs), dirs);
}

bool AppSettings::trackPublisher() {
    return QSettings().value(QLatin1StringView(kTrackPublisher), false).toBool();
}

void AppSettings::setTrackPublisher(bool on) {
    QSettings().setValue(QLatin1StringView(kTrackPublisher), on);
}

bool AppSettings::firstRunDone() {
    return QSettings().value(QLatin1StringView(kFirstRun), false).toBool();
}

void AppSettings::setFirstRunDone(bool done) {
    QSettings().setValue(QLatin1StringView(kFirstRun), done);
}

}  // namespace extwatch
