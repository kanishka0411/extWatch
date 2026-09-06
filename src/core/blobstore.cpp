#include "core/blobstore.h"

#include <QCryptographicHash>
#include <QDir>
#include <QDirIterator>
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
    QFile src(srcPath);
    if (!src.open(QIODevice::ReadOnly)) {
        if (error) {
            *error = QStringLiteral("cannot read %1: %2").arg(srcPath, src.errorString());
        }
        return false;
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
    QFile out(tmp);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (error) {
            *error = QStringLiteral("cannot write %1: %2").arg(tmp, out.errorString());
        }
        return false;
    }
    QCryptographicHash hash(QCryptographicHash::Sha256);
    char buffer[1 << 16];
    qint64 n = 0;
    while ((n = src.read(buffer, sizeof(buffer))) > 0) {
        hash.addData(QByteArrayView(buffer, static_cast<qsizetype>(n)));
        if (out.write(buffer, n) != n) {
            n = -1;
            break;
        }
    }
    out.close();
    if (n < 0 || hash.result() != sha256) {
        QFile::remove(tmp);
        if (error) {
            *error = n < 0 ? QStringLiteral("write failed for %1").arg(tmp)
                           : QStringLiteral("%1 changed while it was being archived").arg(srcPath);
        }
        return false;
    }
    QFile::setPermissions(tmp, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
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

bool BlobStore::verify(const QByteArray& sha256) const {
    bool ok = false;
    const QByteArray actual = sha256File(pathFor(sha256), &ok);
    return ok && actual == sha256;
}

QList<QByteArray> BlobStore::allBlobs() const {
    QList<QByteArray> out;
    QDirIterator it(m_root + QStringLiteral("/blobs"), QDir::Files | QDir::NoDotAndDotDot, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        it.next();
        const QString name = it.fileName();
        if (name.size() == 64) {
            out.append(QByteArray::fromHex(name.toLatin1()));
        }
    }
    return out;
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
