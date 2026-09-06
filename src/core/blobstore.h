#pragma once

#include <QByteArray>
#include <QList>
#include <QString>

#include "core/hashing.h"

namespace extwatch {

// Content-addressed file store: <root>/blobs/<first two hex chars>/<sha256 hex>.
// Identical files across versions and extensions are stored once.
class BlobStore {
public:
    explicit BlobStore(QString rootDir);

    QString rootDir() const { return m_root; }
    QString pathFor(const QByteArray& sha256) const;
    bool has(const QByteArray& sha256) const;

    // Copies srcPath into the store under sha256. Returns true if the blob is present afterwards.
    bool put(const QString& srcPath, const QByteArray& sha256, QString* error = nullptr);

    // Recreates a file tree from stored blobs (used for exports and rollback bundles).
    bool exportTree(const QList<FileEntry>& files, const QString& outDir,
                    QString* error = nullptr) const;

private:
    QString m_root;
};

}  // namespace extwatch
