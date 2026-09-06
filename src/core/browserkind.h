#pragma once

#include <QList>
#include <QString>
#include <QStringView>
#include <optional>

namespace extwatch {

enum class BrowserKind {
    Chrome,
    ChromeBeta,
    ChromeDev,
    ChromeCanary,
    Chromium,
    Edge,
    EdgeBeta,
    EdgeDev,
    Brave,
    BraveBeta,
    BraveNightly,
    Vivaldi,
    Opera,
    Arc,
};

// A candidate browser installation: a user data directory that may or may not exist.
struct BrowserInstall {
    BrowserKind kind;
    QString displayName;
    QString userDataDir;
};

QString browserKindId(BrowserKind kind);    // stable id used in JSON and the database
QString browserKindName(BrowserKind kind);  // human readable
std::optional<BrowserKind> browserKindFromId(QStringView id);

// Every known user-data-dir location for this OS, plus EXTWATCH_USER_DATA_DIRS entries.
QList<BrowserInstall> knownBrowserLocations();

// Parses EXTWATCH_USER_DATA_DIRS="chrome=/path/User Data;brave=/other" (kind defaults to chrome).
QList<BrowserInstall> browserLocationsFromEnvironment();

}  // namespace extwatch
