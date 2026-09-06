#pragma once

#include <QList>
#include <QString>

#include "core/signature.h"

namespace extwatch {

// Loads an extension from a directory, a .zip, or a .crx (CRX2 and CRX3 containers).
// Zip entries below a single top-level folder are flattened so manifest.json sits at the root.
// Untrusted input: archives above 512 MiB, more than 20,000 entries, entries above 128 MiB,
// more than 1 GiB in total or suspicious compression ratios are refused or skipped, with a
// warning for each decision. Only analyzable files are inflated; others keep their size.
QList<SourceFile> loadSourcesFromPackage(const QString& path, QString* error = nullptr,
                                         QStringList* warnings = nullptr);

// Writes the given files into a zip archive.
bool writeZip(const QString& zipPath, const QList<SourceFile>& files, QString* error = nullptr);

// Offset of the zip payload inside a CRX file, or -1 when the data is not a CRX.
qint64 crxZipOffset(const QByteArray& data);

}  // namespace extwatch
