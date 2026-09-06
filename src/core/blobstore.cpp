#include "core/blobstore.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRandomGenerator>

namespace extwatch {

BlobStore::BlobStore(QString rootDir) : m_root(std::move(rootDir)) {}

QString BlobStore::pathFor(const QByteArray& sha256) const {
    const QString hex = toHex(sha256);
    return m_root + QStringLiteral("/blobs/") + hex.left(2) + u'/' + hex;
}

bool BlobStore::has(const QByteArray& sha256) const {
    return QFileInfo::exists(pathFor(sha256));
}

bool BlobStore::put(const QString& srcPath, const QByteArray& sha256, QString* error) {
    if (has(sha256)) {
        return true;
    }
    const QString dst = pathFor(sha256);
    if (!QDir().mkpath(QFileInfo(dst).path())) {
        if (error) {
            *error = QStringLiteral("cannot create %1").arg(QFileInfo(dst).path());
        }
        return false;
    }
    const QString tmp =
        dst + QStringLiteral(".tmp") + QString::number(QRandomGenerator::global()->generate());
    if (!QFile::copy(srcPath, tmp)) {
        if (error) {
            *error = QStringLiteral("cannot copy %1").arg(srcPath);
        }
        return false;
    }
    QFile::setPermissions(tmp, QFileDevice::ReadOwner | QFileDevice::WriteOwner |
                                   QFileDevice::ReadGroup | QFileDevice::ReadOther);
    if (!QFile::rename(tmp, dst)) {
        QFile::remove(tmp);
        if (QFileInfo::exists(dst)) {
            return true;  // another writer got there first
        }
        if (error) {
            *error = QStringLiteral("cannot move blob into place: %1").arg(dst);
        }
        return false;
    }
    return true;
}

bool BlobStore::exportTree(const QList<FileEntry>& files, const QString& outDir,
                           QString* error) const {
    for (const FileEntry& f : files) {
        const QString dst = outDir + u'/' + f.relPath;
        if (!QDir().mkpath(QFileInfo(dst).path())) {
            if (error) {
                *error = QStringLiteral("cannot create %1").arg(QFileInfo(dst).path());
            }
            return false;
        }
        if (QFileInfo::exists(dst)) {
            QFile::remove(dst);
        }
        if (!QFile::copy(pathFor(f.sha256), dst)) {
            if (error) {
                *error = QStringLiteral("missing blob for %1").arg(f.relPath);
            }
            return false;
        }
    }
    return true;
}

}  // namespace extwatch
