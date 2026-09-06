#pragma once

#include <QString>
#include <QStringList>
#include <QUrl>

#include "core/browserkind.h"
#include "core/database.h"

namespace extwatch {

struct ActionResult {
    bool ok = false;
    QString message;
    QString path;
    QString quarantineId;
};

QString quarantineRoot(const QString& dataDir);

enum class MoveOutcome { Moved, CopiedSourceRemains, Failed };

// Moves a directory. Same volume: one rename. Across volumes: copy to a temporary sibling,
// verify the copy against expectedTreeHashHex (or against the source when empty), rename it into
// place, then remove the source. If the source cannot be removed the copy is kept and the caller
// is told, so nothing is ever silently duplicated or lost.
MoveOutcome moveDirectoryVerified(const QString& src, const QString& dst, const QString& expectedTreeHashHex,
                                  QString* error = nullptr);

struct QuarantineRequest {
    qint64 extensionId = 0;  // extensions.id, which pins browser and profile
    QString extId;
    QString browserKind;
    QString userDataDir;
    QString profileDir;
    QString version;
    QString dirName;
    QString treeHash;
    QString versionDirPath;
};

// Moves the installed version directory of exactly this browser profile into
// <dataDir>/quarantine/<random id>/ and records where it came from. The browser then reports the
// extension as corrupted and disables it. Reversible with restoreQuarantine.
ActionResult quarantineVersion(Database& db, const QString& dataDir, const QuarantineRequest& request);

// Moves a quarantined directory back to the exact path it was taken from.
ActionResult restoreQuarantine(Database& db, const QString& dataDir, const QString& quarantineId);

QUrl webStoreUrl(BrowserKind kind, const QString& extId);
QString extensionsPageUrl(BrowserKind kind, const QString& extId);

}  // namespace extwatch
