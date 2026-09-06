#include "core/actions.h"

#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>

namespace extwatch {

QString quarantineRoot(const QString& dataDir) {
    return dataDir + QStringLiteral("/quarantine");
}

namespace {

bool copyDirectory(const QString& src, const QString& dst, QString* error) {
    QDir().mkpath(dst);
    QDirIterator it(src, QDir::Files | QDir::Hidden | QDir::NoDotAndDotDot, QDirIterator::Subdirectories);
    const QDir srcDir(src);
    while (it.hasNext()) {
        const QFileInfo fi = it.nextFileInfo();
        const QString target = dst + u'/' + srcDir.relativeFilePath(fi.filePath());
        QDir().mkpath(QFileInfo(target).path());
        if (!QFile::copy(fi.filePath(), target)) {
            if (error) {
                *error = QStringLiteral("cannot copy %1").arg(fi.filePath());
            }
            return false;
        }
    }
    return true;
}

}  // namespace

bool moveDirectory(const QString& src, const QString& dst, QString* error) {
    if (!QFileInfo(src).isDir()) {
        if (error) {
            *error = QStringLiteral("%1 is not a directory").arg(src);
        }
        return false;
    }
    if (QFileInfo::exists(dst)) {
        if (error) {
            *error = QStringLiteral("%1 already exists").arg(dst);
        }
        return false;
    }
    QDir().mkpath(QFileInfo(dst).path());
    if (QDir().rename(src, dst)) {
        return true;
    }
    if (!copyDirectory(src, dst, error)) {
        QDir(dst).removeRecursively();
        return false;
    }
    if (!QDir(src).removeRecursively()) {
        if (error) {
            *error = QStringLiteral("copied, but could not remove %1").arg(src);
        }
        return false;
    }
    return true;
}

ActionResult quarantineVersionDir(const QString& dataDir, const QString& extId,
                                  const QString& versionDirPath) {
    ActionResult r;
    const QFileInfo info(versionDirPath);
    if (!info.isDir()) {
        r.message = QStringLiteral("The version directory no longer exists: %1").arg(versionDirPath);
        return r;
    }
    const QString target = quarantineRoot(dataDir) + u'/' + extId + u'/' + info.fileName();
    QString error;
    if (!moveDirectory(versionDirPath, target, &error)) {
        r.message = error;
        return r;
    }
    r.ok = true;
    r.path = target;
    r.message = QStringLiteral("Moved %1 to %2").arg(versionDirPath, target);
    return r;
}

ActionResult restoreQuarantined(const QString& dataDir, const QString& extId, const QString& dirName,
                                const QString& extensionsDir) {
    ActionResult r;
    const QString src = quarantineRoot(dataDir) + u'/' + extId + u'/' + dirName;
    const QString dst = extensionsDir + u'/' + extId + u'/' + dirName;
    QString error;
    if (!moveDirectory(src, dst, &error)) {
        r.message = error;
        return r;
    }
    r.ok = true;
    r.path = dst;
    r.message = QStringLiteral("Restored %1").arg(dst);
    return r;
}

QStringList quarantinedDirs(const QString& dataDir, const QString& extId) {
    return QDir(quarantineRoot(dataDir) + u'/' + extId).entryList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);
}

QUrl webStoreUrl(BrowserKind kind, const QString& extId) {
    switch (kind) {
        case BrowserKind::Edge:
        case BrowserKind::EdgeBeta:
        case BrowserKind::EdgeDev:
            return QUrl(QStringLiteral("https://microsoftedge.microsoft.com/addons/detail/") + extId);
        default:
            return QUrl(QStringLiteral("https://chromewebstore.google.com/detail/") + extId);
    }
}

QString extensionsPageUrl(BrowserKind kind, const QString& extId) {
    QString scheme = QStringLiteral("chrome");
    switch (kind) {
        case BrowserKind::Edge:
        case BrowserKind::EdgeBeta:
        case BrowserKind::EdgeDev:
            scheme = QStringLiteral("edge");
            break;
        case BrowserKind::Brave:
        case BrowserKind::BraveBeta:
        case BrowserKind::BraveNightly:
            scheme = QStringLiteral("brave");
            break;
        case BrowserKind::Vivaldi:
            scheme = QStringLiteral("vivaldi");
            break;
        case BrowserKind::Opera:
            scheme = QStringLiteral("opera");
            break;
        default:
            break;
    }
    return QStringLiteral("%1://extensions/?id=%2").arg(scheme, extId);
}

}  // namespace extwatch
