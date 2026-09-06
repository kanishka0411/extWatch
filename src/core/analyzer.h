#pragma once

#include <QList>
#include <QString>
#include <optional>

#include "core/blobstore.h"
#include "core/database.h"
#include "core/manifest.h"
#include "core/rules.h"
#include "core/signature.h"
#include "core/textdiff.h"

namespace extwatch {

// Sources of one archived version, restored from the blob store. With contentForAll false only
// analyzable files are read; the rest carry name and size.
QList<SourceFile> loadSourcesFromArchive(Database& db, const BlobStore& blobs, qint64 versionId,
                                         bool contentForAll = true);

// Returns the stored signature for a version, computing and storing it on first use.
std::optional<Signature> signatureForVersion(Database& db, const BlobStore& blobs, qint64 versionId);

// Computes findings for an event (baseline, updated or pending_version) and stores them on the
// event row. Returns the findings.
QList<Finding> analyzeEvent(Database& db, const BlobStore& blobs, qint64 eventId);

// One file of a version-to-version comparison.
struct FileChange {
    enum class Status { Added, Removed, Modified, Unchanged };
    QString path;
    Status status = Status::Unchanged;
    qint64 oldBytes = 0;
    qint64 newBytes = 0;
    bool binary = false;
};

// Everything the UI and the HTML report need about a change between two versions.
struct ChangeReport {
    QString extId;
    QString name;
    QString browserName;
    QString profileName;
    QString eventKind;
    qint64 eventAt = 0;
    std::optional<VersionRow> from;
    VersionRow to;
    Signature fromSignature;
    Signature toSignature;
    QList<Finding> findings;
    QList<FileChange> files;   // sorted: modified first, then added, removed, unchanged
    QString manifestDiff;      // unified diff of the key-sorted manifests
};

std::optional<ChangeReport> buildChangeReport(Database& db, const BlobStore& blobs, qint64 eventId);

// Compares two version rows directly (used by `extwatch diff` and the version timeline).
std::optional<ChangeReport> buildVersionReport(Database& db, const BlobStore& blobs,
                                               std::optional<qint64> fromVersionId, qint64 toVersionId);

// Display text (prettified) for one file of an archived version. Empty optional if missing.
std::optional<QString> fileDisplayText(Database& db, const BlobStore& blobs, qint64 versionId,
                                       const QString& path);

// Self-contained HTML for sharing. `maxFiles` and `maxLinesPerFile` cap the embedded diffs.
QString renderHtmlReport(Database& db, const BlobStore& blobs, const ChangeReport& report,
                         int maxFiles = 25, int maxLinesPerFile = 600);

}  // namespace extwatch
