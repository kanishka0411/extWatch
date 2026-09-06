#pragma once

#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>

namespace testutil {

inline QString fixturesDir() {
    return QStringLiteral(EXTWATCH_FIXTURES_DIR);
}

inline QString fixtureExtensionDir(const QString& version) {
    return fixturesDir() + QStringLiteral("/extensions/screenshot-tool/") + version;
}

inline QString fixtureExtensionId() {
    QFile f(fixturesDir() + QStringLiteral("/extensions/screenshot-tool/EXPECTED_ID"));
    if (!f.open(QIODevice::ReadOnly)) {
        return {};
    }
    return QString::fromLatin1(f.readAll()).trimmed();
}

inline bool copyDirRecursively(const QString& src, const QString& dst) {
    QDir().mkpath(dst);
    QDirIterator it(src, QDir::Files | QDir::Hidden | QDir::NoDotAndDotDot,
                    QDirIterator::Subdirectories);
    const QDir srcDir(src);
    while (it.hasNext()) {
        const QFileInfo fi = it.nextFileInfo();
        const QString target = dst + u'/' + srcDir.relativeFilePath(fi.filePath());
        QDir().mkpath(QFileInfo(target).path());
        if (!QFile::copy(fi.filePath(), target)) {
            return false;
        }
    }
    return true;
}

inline bool writeJson(const QString& path, const QJsonObject& obj) {
    QDir().mkpath(QFileInfo(path).path());
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        return false;
    }
    f.write(QJsonDocument(obj).toJson());
    return true;
}

inline QJsonObject readJson(const QString& path) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        return {};
    }
    return QJsonDocument::fromJson(f.readAll()).object();
}

// A synthetic Chrome user data directory with one profile and the fixture extension installed
// at the given version (copied from fixtures/). Returns the profile directory.
inline QString makeFakeUserDataDir(const QString& root, const QString& profileDir,
                                   const QString& version, bool enabled = true) {
    const QString extId = fixtureExtensionId();
    QJsonObject infoCache;
    QJsonObject profileInfo;
    profileInfo.insert(QStringLiteral("name"), QStringLiteral("Test Person"));
    infoCache.insert(profileDir, profileInfo);
    QJsonObject profileObj;
    profileObj.insert(QStringLiteral("info_cache"), infoCache);
    QJsonObject localState;
    localState.insert(QStringLiteral("profile"), profileObj);
    writeJson(root + QStringLiteral("/Local State"), localState);

    const QString profilePath = root + u'/' + profileDir;
    const QString versionDir = profilePath + QStringLiteral("/Extensions/") + extId + u'/' + version +
                               QStringLiteral("_0");
    copyDirRecursively(fixtureExtensionDir(version), versionDir);

    QJsonObject record;
    record.insert(QStringLiteral("path"), extId + u'/' + version + QStringLiteral("_0"));
    record.insert(QStringLiteral("location"), 1);
    record.insert(QStringLiteral("from_webstore"), true);
    record.insert(QStringLiteral("disable_reasons"), enabled ? QJsonArray() : QJsonArray{1});
    record.insert(QStringLiteral("first_install_time"), QStringLiteral("13411699200000000"));
    record.insert(QStringLiteral("last_update_time"), QStringLiteral("13411699200000000"));
    record.insert(QStringLiteral("manifest"), readJson(versionDir + QStringLiteral("/manifest.json")));
    QJsonObject settings;
    settings.insert(extId, record);
    // A component extension that must be ignored.
    QJsonObject component;
    component.insert(QStringLiteral("location"), 5);
    component.insert(QStringLiteral("path"), QStringLiteral("/Applications/Browser.app/Resources/web_store"));
    settings.insert(QStringLiteral("ahfgeienlihckogmohjhadlkjgocpleb"), component);
    QJsonObject extensions;
    extensions.insert(QStringLiteral("settings"), settings);
    QJsonObject securePrefs;
    securePrefs.insert(QStringLiteral("extensions"), extensions);
    writeJson(profilePath + QStringLiteral("/Secure Preferences"), securePrefs);
    return profilePath;
}

// Simulates a silent update: a new version directory appears and the prefs switch to it.
inline void simulateUpdate(const QString& profilePath, const QString& newVersion,
                           bool switchPrefs = true) {
    const QString extId = fixtureExtensionId();
    const QString versionDir = profilePath + QStringLiteral("/Extensions/") + extId + u'/' +
                               newVersion + QStringLiteral("_0");
    copyDirRecursively(fixtureExtensionDir(newVersion), versionDir);
    if (!switchPrefs) {
        return;
    }
    const QString prefsPath = profilePath + QStringLiteral("/Secure Preferences");
    QJsonObject prefs = readJson(prefsPath);
    QJsonObject extensions = prefs.value(QStringLiteral("extensions")).toObject();
    QJsonObject settings = extensions.value(QStringLiteral("settings")).toObject();
    QJsonObject record = settings.value(extId).toObject();
    record.insert(QStringLiteral("path"), extId + u'/' + newVersion + QStringLiteral("_0"));
    record.insert(QStringLiteral("manifest"), readJson(versionDir + QStringLiteral("/manifest.json")));
    settings.insert(extId, record);
    extensions.insert(QStringLiteral("settings"), settings);
    prefs.insert(QStringLiteral("extensions"), extensions);
    writeJson(prefsPath, prefs);
}

}  // namespace testutil
