#include "core/package.h"

#include <miniz.h>

#include <QFile>
#include <QFileInfo>
#include <QtEndian>
#include <algorithm>
#include <cstring>

namespace extwatch {

qint64 crxZipOffset(const QByteArray& data) {
    if (data.size() < 16 || !data.startsWith("Cr24")) {
        return -1;
    }
    const quint32 version = qFromLittleEndian<quint32>(data.constData() + 4);
    if (version == 3) {
        const quint32 headerSize = qFromLittleEndian<quint32>(data.constData() + 8);
        const qint64 offset = 12 + static_cast<qint64>(headerSize);
        return offset < data.size() ? offset : -1;
    }
    if (version == 2) {
        const quint32 keySize = qFromLittleEndian<quint32>(data.constData() + 8);
        const quint32 sigSize = qFromLittleEndian<quint32>(data.constData() + 12);
        const qint64 offset = 16 + static_cast<qint64>(keySize) + static_cast<qint64>(sigSize);
        return offset < data.size() ? offset : -1;
    }
    return -1;
}

namespace {

constexpr qint64 kMaxArchiveBytes = 512LL * 1024 * 1024;
constexpr mz_uint kMaxEntries = 20000;
constexpr qint64 kMaxEntryBytes = kMaxAnalyzedBytes;
constexpr qint64 kMaxTotalBytes = kMaxLoadedBytes;
constexpr qint64 kMaxRatio = 200;

QList<SourceFile> readZip(const QByteArray& data, QString* error, QStringList* warnings) {
    QList<SourceFile> out;
    qint64 total = 0;
    mz_zip_archive zip;
    std::memset(&zip, 0, sizeof(zip));
    if (!mz_zip_reader_init_mem(&zip, data.constData(), static_cast<size_t>(data.size()), 0)) {
        if (error) {
            *error = QStringLiteral("not a zip archive");
        }
        return out;
    }
    const mz_uint count = mz_zip_reader_get_num_files(&zip);
    if (count > kMaxEntries) {
        if (warnings) warnings->append(QStringLiteral("archive has %1 entries; only the first %2 are read").arg(count).arg(kMaxEntries));
    }
    for (mz_uint i = 0; i < count && i < kMaxEntries; ++i) {
        if (mz_zip_reader_is_file_a_directory(&zip, i)) {
            continue;
        }
        mz_zip_archive_file_stat st;
        if (!mz_zip_reader_file_stat(&zip, i, &st)) {
            continue;
        }
        QString name = QString::fromUtf8(st.m_filename).replace(u'\\', u'/');
        while (name.startsWith(u'/')) {
            name.remove(0, 1);
        }
        if (name.isEmpty() || name.contains(QStringLiteral("../"))) {
            continue;
        }
        const qint64 uncompressed = static_cast<qint64>(st.m_uncomp_size);
        const qint64 compressed = static_cast<qint64>(st.m_comp_size);
        SourceFile file;
        file.path = name;
        file.size = uncompressed;
        if (uncompressed > kMaxEntryBytes) {
            if (warnings) warnings->append(QStringLiteral("%1 is %2 MiB; not inflated").arg(name).arg(uncompressed / (1024 * 1024)));
            out.append(file);
            continue;
        }
        if (uncompressed > kMaxRatio * qMax<qint64>(compressed, 1024)) {
            if (warnings) warnings->append(QStringLiteral("%1 inflates %2x; not inflated").arg(name).arg(uncompressed / qMax<qint64>(compressed, 1)));
            out.append(file);
            continue;
        }
        if (!isAnalyzablePath(name)) {
            out.append(file);  // size and name are enough for non-code files
            continue;
        }
        if (total + uncompressed > kMaxTotalBytes) {
            if (warnings) warnings->append(QStringLiteral("archive inflates beyond %1 MiB; remaining entries not read").arg(kMaxTotalBytes / (1024 * 1024)));
            out.append(file);
            continue;
        }
        size_t size = 0;
        void* buf = mz_zip_reader_extract_to_heap(&zip, i, &size, 0);
        if (!buf) {
            if (warnings) warnings->append(QStringLiteral("%1 could not be inflated").arg(name));
            out.append(file);
            continue;
        }
        total += static_cast<qint64>(size);
        file.content = QByteArray(static_cast<const char*>(buf), static_cast<qsizetype>(size));
        file.size = file.content.size();
        mz_free(buf);
        out.append(file);
    }
    mz_zip_reader_end(&zip);

    // Flatten a single top-level folder ("my-extension/manifest.json").
    bool rootManifest = false;
    QString prefix;
    bool singlePrefix = true;
    for (const SourceFile& f : out) {
        if (f.path == QStringLiteral("manifest.json")) {
            rootManifest = true;
        }
        const qsizetype slash = f.path.indexOf(u'/');
        const QString top = slash < 0 ? QString() : f.path.left(slash + 1);
        if (prefix.isEmpty() && !top.isEmpty()) {
            prefix = top;
        } else if (top != prefix) {
            singlePrefix = false;
        }
    }
    if (!rootManifest && singlePrefix && !prefix.isEmpty()) {
        for (SourceFile& f : out) {
            f.path.remove(0, prefix.size());
        }
    }
    std::sort(out.begin(), out.end(),
              [](const SourceFile& a, const SourceFile& b) { return a.path < b.path; });
    return out;
}

}  // namespace

QList<SourceFile> loadSourcesFromPackage(const QString& path, QString* error, QStringList* warnings) {
    const QFileInfo info(path);
    if (info.isDir()) {
        return loadSourcesFromDir(info.absoluteFilePath(), false);
    }
    if (info.size() > kMaxArchiveBytes) {
        if (error) {
            *error = QStringLiteral("%1 is larger than %2 MiB").arg(path).arg(kMaxArchiveBytes / (1024 * 1024));
        }
        return {};
    }
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        if (error) {
            *error = QStringLiteral("cannot open %1").arg(path);
        }
        return {};
    }
    QByteArray data = f.readAll();
    const qint64 crx = crxZipOffset(data);
    if (crx >= 0) {
        data = data.mid(crx);
    }
    return readZip(data, error, warnings);
}

bool writeZip(const QString& zipPath, const QList<SourceFile>& files, QString* error) {
    mz_zip_archive zip;
    std::memset(&zip, 0, sizeof(zip));
    if (!mz_zip_writer_init_file(&zip, zipPath.toUtf8().constData(), 0)) {
        if (error) {
            *error = QStringLiteral("cannot create %1").arg(zipPath);
        }
        return false;
    }
    for (const SourceFile& f : files) {
        if (!mz_zip_writer_add_mem(&zip, f.path.toUtf8().constData(), f.content.constData(),
                                   static_cast<size_t>(f.content.size()), MZ_DEFAULT_COMPRESSION)) {
            if (error) {
                *error = QStringLiteral("cannot add %1").arg(f.path);
            }
            mz_zip_writer_end(&zip);
            return false;
        }
    }
    const bool ok = mz_zip_writer_finalize_archive(&zip);
    mz_zip_writer_end(&zip);
    if (!ok && error) {
        *error = QStringLiteral("cannot finalize %1").arg(zipPath);
    }
    return ok;
}

}  // namespace extwatch
