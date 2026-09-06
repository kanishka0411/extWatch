#include "core/hashing.h"

#include <QCryptographicHash>
#include <QDir>
#include <QDirIterator>
#include <QDateTime>
#include <QFile>
#include <algorithm>

namespace extwatch {

QByteArray sha256File(const QString& path, bool* ok) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        if (ok) {
            *ok = false;
        }
        return {};
    }
    QCryptographicHash hash(QCryptographicHash::Sha256);
    const bool added = hash.addData(&f);
    if (ok) {
        *ok = added;
    }
    return added ? hash.result() : QByteArray();
}

QString toHex(const QByteArray& bytes) {
    return QString::fromLatin1(bytes.toHex());
}

QString directoryFingerprint(const QString& rootDir) {
    // Per-file path, size and mtime, hashed together: a swap of two files that keeps the totals
    // identical still changes the fingerprint. Content is not read.
    qint64 files = 0;
    qint64 bytes = 0;
    qint64 newest = 0;
    QList<QString> lines;
    QDirIterator it(rootDir, QDir::Files | QDir::Hidden | QDir::NoSymLinks | QDir::NoDotAndDotDot,
                    QDirIterator::Subdirectories);
    const QDir root(rootDir);
    while (it.hasNext()) {
        const QFileInfo fi = it.nextFileInfo();
        ++files;
        bytes += fi.size();
        const qint64 mtime = fi.lastModified().toMSecsSinceEpoch();
        newest = qMax(newest, mtime);
        lines.append(root.relativeFilePath(fi.filePath()) + u'|' + QString::number(fi.size()) + u'|' + QString::number(mtime));
    }
    std::sort(lines.begin(), lines.end());
    QCryptographicHash h(QCryptographicHash::Sha256);
    for (const QString& l : lines) {
        h.addData(l.toUtf8());
        h.addData(QByteArrayView("\n", 1));
    }
    return QStringLiteral("%1:%2:%3:%4").arg(files).arg(bytes).arg(newest).arg(QString::fromLatin1(h.result().toHex().left(16)));
}

TreeSnapshot hashTree(const QString& rootDir) {
    TreeSnapshot snap;
    const QDir root(rootDir);
    QDirIterator it(rootDir, QDir::Files | QDir::Hidden | QDir::NoSymLinks | QDir::NoDotAndDotDot,
                    QDirIterator::Subdirectories);
    while (it.hasNext()) {
        const QFileInfo fi = it.nextFileInfo();
        bool ok = false;
        const QByteArray sha = sha256File(fi.filePath(), &ok);
        if (!ok) {
            snap.warnings.append(QStringLiteral("unreadable: %1").arg(fi.filePath()));
            continue;
        }
        snap.files.append({root.relativeFilePath(fi.filePath()), sha, fi.size()});
        snap.totalBytes += fi.size();
        snap.newestMtimeMs = qMax(snap.newestMtimeMs, fi.lastModified().toMSecsSinceEpoch());
    }
    std::sort(snap.files.begin(), snap.files.end(), [](const FileEntry& a, const FileEntry& b) {
        return a.relPath.toUtf8() < b.relPath.toUtf8();
    });
    QCryptographicHash tree(QCryptographicHash::Sha256);
    for (const FileEntry& f : snap.files) {
        tree.addData(f.relPath.toUtf8());
        tree.addData(QByteArrayView("\0", 1));
        tree.addData(f.sha256.toHex());
        tree.addData(QByteArrayView("\n", 1));
    }
    snap.treeHash = tree.result();
    return snap;
}

}  // namespace extwatch
