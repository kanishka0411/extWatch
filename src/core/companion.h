#pragma once

#include <QList>
#include <QString>
#include <QStringList>

#include "core/browserkind.h"

namespace extwatch {

// Facts about the bundled companion extension and the native messaging host it talks to.
QString nativeHostName();          // "app.extwatch.host"
QString companionExtensionId();    // derived from the key in companion/manifest.json
QString ipcServerName();           // QLocalServer name shared by the app and the host processes

// True when the process was launched by a browser as a native messaging host: the first
// argument is the calling extension's origin.
bool launchedAsNativeHost(const QStringList& args);

struct HostRegistration {
    BrowserKind kind;
    QString location;  // manifest path (Unix) or registry key (Windows)
    bool ok = false;
    QString error;
};

// Writes the native messaging host manifest for every browser in `browsers` (user level, no
// admin rights). `executable` is the ExtWatch binary the browser should launch.
QList<HostRegistration> registerNativeHost(const QString& executable, const QString& dataDir,
                                           const QList<BrowserInstall>& browsers);
QList<HostRegistration> unregisterNativeHost(const QList<BrowserInstall>& browsers);

// Copies the embedded companion extension to <dataDir>/companion and returns that path.
QString extractCompanion(const QString& dataDir, QString* error = nullptr);

// SHA-256 over the embedded companion files, and over the extracted copy; a mismatch means the
// files on disk were modified after installation.
QString companionEmbeddedHash();
QString companionExtractedHash(const QString& dataDir);
bool companionExtracted(const QString& dataDir);

}  // namespace extwatch
