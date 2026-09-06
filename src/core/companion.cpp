#include "core/companion.h"

#include <QCryptographicHash>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSettings>

#include "core/crxid.h"

namespace extwatch {

QString nativeHostName() {
    return QStringLiteral("app.extwatch.host");
}

QString companionExtensionId() {
    static const QString id = [] {
        QFile f(QStringLiteral(":/companion/manifest.json"));
        if (!f.open(QIODevice::ReadOnly)) {
            return QString();
        }
        const QJsonObject manifest = QJsonDocument::fromJson(f.readAll()).object();
        return extensionIdFromManifestKey(manifest.value(QStringLiteral("key")).toString());
    }();
    return id;
}

QString ipcServerName() {
    QString user = qEnvironmentVariable("USER");
    if (user.isEmpty()) {
        user = qEnvironmentVariable("USERNAME");
    }
    if (user.isEmpty()) {
        user = QStringLiteral("default");
    }
    return QStringLiteral("extwatch-ipc-") + user;
}

bool launchedAsNativeHost(const QStringList& args) {
    return !args.isEmpty() && args.first().startsWith(QStringLiteral("chrome-extension://"));
}

namespace {

QJsonObject hostManifest(const QString& executable) {
    QJsonObject m;
    m.insert(QStringLiteral("name"), nativeHostName());
    m.insert(QStringLiteral("description"), QStringLiteral("ExtWatch native messaging host"));
    m.insert(QStringLiteral("path"), QDir::toNativeSeparators(executable));
    m.insert(QStringLiteral("type"), QStringLiteral("stdio"));
    m.insert(QStringLiteral("allowed_origins"),
             QJsonArray{QStringLiteral("chrome-extension://%1/").arg(companionExtensionId())});
    return m;
}

bool writeManifest(const QString& path, const QString& executable, QString* error) {
    if (!QDir().mkpath(QFileInfo(path).path())) {
        if (error) *error = QStringLiteral("cannot create %1").arg(QFileInfo(path).path());
        return false;
    }
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (error) *error = f.errorString();
        return false;
    }
    f.write(QJsonDocument(hostManifest(executable)).toJson(QJsonDocument::Indented));
    return true;
}

#ifdef Q_OS_WIN
QString registryKeyFor(BrowserKind kind) {
    switch (kind) {
        case BrowserKind::Chrome: case BrowserKind::ChromeBeta: case BrowserKind::ChromeDev: case BrowserKind::ChromeCanary:
            return QStringLiteral("HKEY_CURRENT_USER\\Software\\Google\\Chrome\\NativeMessagingHosts\\");
        case BrowserKind::Chromium:
            return QStringLiteral("HKEY_CURRENT_USER\\Software\\Chromium\\NativeMessagingHosts\\");
        case BrowserKind::Edge: case BrowserKind::EdgeBeta: case BrowserKind::EdgeDev:
            return QStringLiteral("HKEY_CURRENT_USER\\Software\\Microsoft\\Edge\\NativeMessagingHosts\\");
        case BrowserKind::Brave: case BrowserKind::BraveBeta: case BrowserKind::BraveNightly:
            return QStringLiteral("HKEY_CURRENT_USER\\Software\\BraveSoftware\\Brave\\NativeMessagingHosts\\");
        case BrowserKind::Vivaldi:
            return QStringLiteral("HKEY_CURRENT_USER\\Software\\Vivaldi\\NativeMessagingHosts\\");
        default:
            return QString();
    }
}
#endif

}  // namespace

QList<HostRegistration> registerNativeHost(const QString& executable, const QString& dataDir,
                                           const QList<BrowserInstall>& browsers) {
    QList<HostRegistration> out;
    QStringList done;
    for (const BrowserInstall& b : browsers) {
        HostRegistration r;
        r.kind = b.kind;
#ifdef Q_OS_WIN
        const QString key = registryKeyFor(b.kind);
        if (key.isEmpty() || done.contains(key)) {
            continue;
        }
        done.append(key);
        const QString manifestPath = QDir::toNativeSeparators(dataDir + QStringLiteral("/native-host/") + browserKindId(b.kind) + QStringLiteral("/app.extwatch.host.json"));
        r.location = key + nativeHostName();
        if (!writeManifest(manifestPath, executable, &r.error)) {
            out.append(r);
            continue;
        }
        QSettings reg(key + nativeHostName(), QSettings::NativeFormat);
        reg.setValue(QStringLiteral("Default"), manifestPath);
        reg.sync();
        r.ok = reg.status() == QSettings::NoError;
        if (!r.ok) r.error = QStringLiteral("registry write failed");
#else
        Q_UNUSED(dataDir);
        r.location = b.userDataDir + QStringLiteral("/NativeMessagingHosts/") + nativeHostName() + QStringLiteral(".json");
        if (done.contains(r.location)) {
            continue;
        }
        done.append(r.location);
        if (!QFileInfo(b.userDataDir).isDir()) {
            r.error = QStringLiteral("browser directory not found");
            out.append(r);
            continue;
        }
        r.ok = writeManifest(r.location, executable, &r.error);
#endif
        out.append(r);
    }
    return out;
}

QList<HostRegistration> unregisterNativeHost(const QList<BrowserInstall>& browsers) {
    QList<HostRegistration> out;
    for (const BrowserInstall& b : browsers) {
        HostRegistration r;
        r.kind = b.kind;
#ifdef Q_OS_WIN
        const QString key = registryKeyFor(b.kind);
        if (key.isEmpty()) continue;
        QSettings reg(key, QSettings::NativeFormat);
        reg.remove(nativeHostName());
        r.location = key + nativeHostName();
        r.ok = true;
#else
        r.location = b.userDataDir + QStringLiteral("/NativeMessagingHosts/") + nativeHostName() + QStringLiteral(".json");
        r.ok = !QFileInfo::exists(r.location) || QFile::remove(r.location);
#endif
        out.append(r);
    }
    return out;
}

namespace {

QString hashTreeOf(const QString& root, const QStringList& relPaths) {
    QCryptographicHash hash(QCryptographicHash::Sha256);
    for (const QString& rel : relPaths) {
        QFile f(root + u'/' + rel);
        if (!f.open(QIODevice::ReadOnly)) {
            return QString();
        }
        hash.addData(rel.toUtf8());
        hash.addData(QByteArrayView("\0", 1));
        hash.addData(f.readAll());
    }
    return QString::fromLatin1(hash.result().toHex());
}

QStringList companionFiles() {
    QStringList out;
    QDirIterator it(QStringLiteral(":/companion"), QDirIterator::Subdirectories);
    while (it.hasNext()) {
        const QString resource = it.next();
        if (!QFileInfo(resource).isDir()) {
            out.append(resource.mid(QStringLiteral(":/companion/").size()));
        }
    }
    out.sort();
    return out;
}

}  // namespace

QString companionEmbeddedHash() {
    return hashTreeOf(QStringLiteral(":/companion"), companionFiles());
}

QString companionExtractedHash(const QString& dataDir) {
    return hashTreeOf(dataDir + QStringLiteral("/companion"), companionFiles());
}

bool companionExtracted(const QString& dataDir) {
    return QFileInfo::exists(dataDir + QStringLiteral("/companion/manifest.json"));
}

QString extractCompanion(const QString& dataDir, QString* error) {
    const QString target = dataDir + QStringLiteral("/companion");
    QDirIterator it(QStringLiteral(":/companion"), QDirIterator::Subdirectories);
    while (it.hasNext()) {
        const QString resource = it.next();
        const QFileInfo info(resource);
        if (info.isDir()) {
            continue;
        }
        const QString rel = resource.mid(QStringLiteral(":/companion/").size());
        const QString dst = target + u'/' + rel;
        QDir().mkpath(QFileInfo(dst).path());
        QFile src(resource);
        QFile out(dst);
        if (!src.open(QIODevice::ReadOnly) || !out.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            if (error) *error = QStringLiteral("cannot write %1").arg(dst);
            return QString();
        }
        out.write(src.readAll());
    }
    return target;
}

}  // namespace extwatch
