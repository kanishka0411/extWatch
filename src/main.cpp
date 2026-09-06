#include <QApplication>
#include <QCoreApplication>
#include <QStringList>

#include "app/trayapp.h"
#include "cli/cli.h"
#include "core/companion.h"
#include "nativehost/nativehost.h"
#include "core/scanner.h"
#include "extwatch/version.h"

#ifdef Q_OS_WIN
#include <windows.h>
#endif

namespace {

void setApplicationNames(QCoreApplication& app) {
    app.setOrganizationName(QStringLiteral("ExtWatch"));
    app.setOrganizationDomain(QStringLiteral("extwatch.app"));
    app.setApplicationName(QStringLiteral("ExtWatch"));
    app.setApplicationVersion(QStringLiteral(EXTWATCH_VERSION));
}

}  // namespace

int main(int argc, char* argv[]) {
    QStringList args;
    for (int i = 1; i < argc; ++i) {
        args.append(QString::fromLocal8Bit(argv[i]));
    }

    if (extwatch::launchedAsNativeHost(args)) {
        QCoreApplication app(argc, argv);
        setApplicationNames(app);
        return extwatch::runNativeHost(args);
    }

    if (extwatch::cli::wantsCli(args)) {
        QCoreApplication app(argc, argv);
        setApplicationNames(app);
        return extwatch::cli::run(args);
    }

#ifdef Q_OS_WIN
    // Built as a console program so the CLI has stdout; the tray app does not need the window.
    FreeConsole();
#endif
    QApplication app(argc, argv);
    setApplicationNames(app);
    app.setQuitOnLastWindowClosed(false);

    QString dataDir = extwatch::defaultDataDir();
    QString screenshot;
    for (qsizetype i = 0; i + 1 < args.size(); ++i) {
        if (args.at(i) == QStringLiteral("--data-dir")) {
            dataDir = args.at(i + 1);
        } else if (args.at(i) == QStringLiteral("--screenshot")) {
            screenshot = args.at(i + 1);  // debugging aid: grab the window after the first scan
        }
    }
    extwatch::TrayApp tray(dataDir);
    tray.setScreenshotPath(screenshot);
    tray.setShowWindowOnStart(args.contains(QStringLiteral("--show")));
    QString error;
    if (!tray.start(&error)) {
        return 1;
    }
    return app.exec();
}
