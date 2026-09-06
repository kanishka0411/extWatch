#include "core/actions.h"

#include <QDateTime>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QUuid>

#include "core/hashing.h"

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

MoveOutcome moveDirectoryVerified(const QString& src, const QString& dst, const QString& expectedTreeHashHex,
                                  QString* error) {
    if (!QFileInfo(src).isDir()) {
        if (error) *error = QStringLiteral("%1 is not a directory").arg(src);
        return MoveOutcome::Failed;
    }
    if (QFileInfo::exists(dst)) {
        if (error) *error = QStringLiteral("%1 already exists").arg(dst);
        return MoveOutcome::Failed;
    }
    QDir().mkpath(QFileInfo(dst).path());
    if (QDir().rename(src, dst)) {
        return MoveOutcome::Moved;
    }
    // Different volume: copy, verify, swap in, then remove the original.
    const QString expected = expectedTreeHashHex.isEmpty() ? toHex(hashTree(src).treeHash) : expectedTreeHashHex;
    const QString partial = dst + QStringLiteral(".partial");
    QDir(partial).removeRecursively();
    if (!copyDirectory(src, partial, error)) {
        QDir(partial).removeRecursively();
        return MoveOutcome::Failed;
    }
    if (toHex(hashTree(partial).treeHash) != expected) {
        QDir(partial).removeRecursively();
        if (error) *error = QStringLiteral("the copy of %1 does not match the original; it changed while being moved").arg(src);
        return MoveOutcome::Failed;
    }
    if (!QDir().rename(partial, dst)) {
        QDir(partial).removeRecursively();
        if (error) *error = QStringLiteral("cannot move the copy into %1").arg(dst);
        return MoveOutcome::Failed;
    }
    if (!QDir(src).removeRecursively()) {
        if (error) *error = QStringLiteral("copied to %1, but the original at %2 could not be removed").arg(dst, src);
        return MoveOutcome::CopiedSourceRemains;
    }
    return MoveOutcome::Moved;
}

ActionResult quarantineVersion(Database& db, const QString& dataDir, const QuarantineRequest& req) {
    ActionResult r;
    if (!QFileInfo(req.versionDirPath).isDir()) {
        r.message = QStringLiteral("The version directory no longer exists: %1").arg(req.versionDirPath);
        return r;
    }
    QuarantineRow row;
    row.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
    row.extensionId = req.extensionId;
    row.extId = req.extId;
    row.browserKind = req.browserKind;
    row.userDataDir = req.userDataDir;
    row.profileDir = req.profileDir;
    row.version = req.version;
    row.dirName = req.dirName;
    row.treeHash = req.treeHash;
    row.originalPath = QDir::cleanPath(req.versionDirPath);
    row.quarantinePath = quarantineRoot(dataDir) + u'/' + row.id;
    row.createdAt = QDateTime::currentSecsSinceEpoch();
    QDir().mkpath(quarantineRoot(dataDir));
    QFile::setPermissions(quarantineRoot(dataDir), QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);

    QString error;
    const MoveOutcome outcome = moveDirectoryVerified(row.originalPath, row.quarantinePath, req.treeHash, &error);
    if (outcome == MoveOutcome::Failed) {
        r.message = error;
        return r;
    }
    row.state = outcome == MoveOutcome::Moved ? QStringLiteral("quarantined") : QStringLiteral("copied_source_present");
    if (!db.insertQuarantine(row)) {
        // The files are safe in quarantine; without a record they could not be restored, so put them back.
        moveDirectoryVerified(row.quarantinePath, row.originalPath, req.treeHash, nullptr);
        r.message = QStringLiteral("could not record the quarantine: %1").arg(db.lastError());
        return r;
    }
    r.ok = true;
    r.quarantineId = row.id;
    r.path = row.quarantinePath;
    r.message = outcome == MoveOutcome::Moved
                    ? QStringLiteral("Moved %1 to quarantine %2.").arg(row.originalPath, row.id)
                    : QStringLiteral("Copied %1 to quarantine %2, but the original could not be removed: %3")
                          .arg(row.originalPath, row.id, error);
    return r;
}

ActionResult restoreQuarantine(Database& db, const QString& dataDir, const QString& quarantineId) {
    Q_UNUSED(dataDir);
    ActionResult r;
    const std::optional<QuarantineRow> row = db.quarantineById(quarantineId);
    if (!row) {
        r.message = QStringLiteral("unknown quarantine %1").arg(quarantineId);
        return r;
    }
    if (row->state == QStringLiteral("restored")) {
        r.message = QStringLiteral("quarantine %1 was already restored").arg(quarantineId);
        return r;
    }
    if (QFileInfo::exists(row->originalPath)) {
        r.message = QStringLiteral("%1 already exists; the browser may have reinstalled the extension. Remove it first.").arg(row->originalPath);
        return r;
    }
    QString error;
    const MoveOutcome outcome = moveDirectoryVerified(row->quarantinePath, row->originalPath, row->treeHash, &error);
    if (outcome == MoveOutcome::Failed) {
        r.message = error;
        return r;
    }
    db.setQuarantineState(quarantineId, QStringLiteral("restored"));
    r.ok = true;
    r.path = row->originalPath;
    r.message = QStringLiteral("Restored %1").arg(row->originalPath);
    if (outcome == MoveOutcome::CopiedSourceRemains) {
        r.message += QStringLiteral(" (the quarantine copy could not be removed: %1)").arg(error);
    }
    return r;
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
