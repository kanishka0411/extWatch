#include "core/autostart.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSettings>

namespace extwatch {

namespace {

QString executablePath() {
    return QDir::toNativeSeparators(QCoreApplication::applicationFilePath());
}

#if defined(Q_OS_MACOS)
QString plistPath() {
    return QDir::homePath() + QStringLiteral("/Library/LaunchAgents/app.extwatch.tray.plist");
}
#elif !defined(Q_OS_WIN)
QString desktopPath() {
    const QString cfg = qEnvironmentVariable("XDG_CONFIG_HOME", QDir::homePath() + QStringLiteral("/.config"));
    return cfg + QStringLiteral("/autostart/extwatch.desktop");
}
#endif

}  // namespace

bool isAutostartEnabled() {
#if defined(Q_OS_MACOS)
    return QFileInfo::exists(plistPath());
#elif defined(Q_OS_WIN)
    QSettings run(QStringLiteral("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
                  QSettings::NativeFormat);
    return run.contains(QStringLiteral("ExtWatch"));
#else
    return QFileInfo::exists(desktopPath());
#endif
}

bool setAutostartEnabled(bool enabled, QString* error) {
#if defined(Q_OS_MACOS)
    const QString path = plistPath();
    if (!enabled) {
        return !QFileInfo::exists(path) || QFile::remove(path);
    }
    QDir().mkpath(QFileInfo(path).path());
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (error) *error = f.errorString();
        return false;
    }
    // A bundled app is launched through its executable; the CLI symlink works the same way.
    f.write(QStringLiteral(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                "<plist version=\"1.0\"><dict>\n"
                "  <key>Label</key><string>app.extwatch.tray</string>\n"
                "  <key>ProgramArguments</key><array><string>%1</string></array>\n"
                "  <key>RunAtLoad</key><true/>\n"
                "  <key>ProcessType</key><string>Interactive</string>\n"
                "</dict></plist>\n")
                .arg(executablePath().toHtmlEscaped())
                .toUtf8());
    return true;
#elif defined(Q_OS_WIN)
    QSettings run(QStringLiteral("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
                  QSettings::NativeFormat);
    if (enabled) {
        run.setValue(QStringLiteral("ExtWatch"), QStringLiteral("\"%1\"").arg(executablePath()));
    } else {
        run.remove(QStringLiteral("ExtWatch"));
    }
    run.sync();
    if (run.status() != QSettings::NoError && error) {
        *error = QStringLiteral("registry write failed");
    }
    return run.status() == QSettings::NoError;
#else
    const QString path = desktopPath();
    if (!enabled) {
        return !QFileInfo::exists(path) || QFile::remove(path);
    }
    QDir().mkpath(QFileInfo(path).path());
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (error) *error = f.errorString();
        return false;
    }
    // Desktop-entry Exec values must be quoted and have backslashes, quotes and $ escaped.
    QString exec = executablePath();
    exec.replace(u'\\', QStringLiteral("\\\\"));
    exec.replace(u'"', QStringLiteral("\\\""));
    exec.replace(u'$', QStringLiteral("\\$"));
    f.write(QStringLiteral("[Desktop Entry]\nType=Application\nName=ExtWatch\nComment=Watches browser extensions for silent updates\n"
                           "Exec=\"%1\"\nIcon=extwatch\nTerminal=false\nX-GNOME-Autostart-enabled=true\n")
                .arg(exec)
                .toUtf8());
    return true;
#endif
}

}  // namespace extwatch
