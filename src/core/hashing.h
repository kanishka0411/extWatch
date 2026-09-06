#pragma once

#include <QByteArray>
#include <QList>
#include <QString>
#include <QStringList>

namespace extwatch {

struct FileEntry {
    QString relPath;    // forward slashes, relative to the extension root
    QByteArray sha256;  // raw 32 bytes
    qint64 size = 0;
};

struct TreeSnapshot {
    QList<FileEntry> files;  // sorted by relPath (UTF-8 byte order)
    QByteArray treeHash;     // sha256 over "path\0hexhash\n" lines
    qint64 totalBytes = 0;
    QStringList warnings;
};

QByteArray sha256File(const QString& path, bool* ok);
QString toHex(const QByteArray& bytes);

// Hashes every regular file under rootDir (symlinks skipped). Deterministic for identical trees.
TreeSnapshot hashTree(const QString& rootDir);

}  // namespace extwatch
