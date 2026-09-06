#pragma once

#include <QString>
#include <QStringList>
#include <QUrl>

#include "core/browserkind.h"

namespace extwatch {

struct ActionResult {
    bool ok = false;
    QString message;
    QString path;
};

QString quarantineRoot(const QString& dataDir);

// Moves an installed version directory into <dataDir>/quarantine/<extId>/<dirName>. The browser
// then reports the extension as corrupted and disables it. Reversible with restoreQuarantined.
ActionResult quarantineVersionDir(const QString& dataDir, const QString& extId,
                                  const QString& versionDirPath);

// Moves a quarantined directory back under <extensionsDir>/<extId>/.
ActionResult restoreQuarantined(const QString& dataDir, const QString& extId, const QString& dirName,
                                const QString& extensionsDir);

QStringList quarantinedDirs(const QString& dataDir, const QString& extId);

// Moves a directory, falling back to copy-and-delete across volumes.
bool moveDirectory(const QString& src, const QString& dst, QString* error = nullptr);

QUrl webStoreUrl(BrowserKind kind, const QString& extId);
QString extensionsPageUrl(BrowserKind kind, const QString& extId);

}  // namespace extwatch
