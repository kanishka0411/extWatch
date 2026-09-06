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

QList<SourceFile> readZip(const QByteArray& data, QString* error) {
    QList<SourceFile> out;
    mz_zip_archive zip;
    std::memset(&zip, 0, sizeof(zip));
    if (!mz_zip_reader_init_mem(&zip, data.constData(), static_cast<size_t>(data.size()), 0)) {
        if (error) {
            *error = QStringLiteral("not a zip archive");
        }
        return out;
    }
    const mz_uint count = mz_zip_reader_get_num_files(&zip);
    for (mz_uint i = 0; i < count; ++i) {
        if (mz_zip_reader_is_file_a_directory(&zip, i)) {
            continue;
        }
        mz_zip_archive_file_stat st;
        if (!mz_zip_reader_file_stat(&zip, i, &st)) {
            continue;
        }
        size_t size = 0;
        void* buf = mz_zip_reader_extract_to_heap(&zip, i, &size, 0);
        if (!buf) {
            continue;
        }
        QString name = QString::fromUtf8(st.m_filename).replace(u'\\', u'/');
        while (name.startsWith(u'/')) {
            name.remove(0, 1);
        }
        if (name.isEmpty() || name.contains(QStringLiteral("../"))) {
            mz_free(buf);
            continue;
        }
        out.append({name, QByteArray(static_cast<const char*>(buf), static_cast<qsizetype>(size))});
        mz_free(buf);
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

QList<SourceFile> loadSourcesFromPackage(const QString& path, QString* error) {
    const QFileInfo info(path);
    if (info.isDir()) {
        return loadSourcesFromDir(info.absoluteFilePath());
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
    return readZip(data, error);
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
