#include "core/browserkind.h"

#include <QDir>
#include <QtGlobal>

namespace extwatch {

namespace {

struct KindInfo {
    BrowserKind kind;
    const char* id;
    const char* name;
};

constexpr KindInfo kKinds[] = {
    {BrowserKind::Chrome, "chrome", "Google Chrome"},
    {BrowserKind::ChromeBeta, "chrome-beta", "Google Chrome Beta"},
    {BrowserKind::ChromeDev, "chrome-dev", "Google Chrome Dev"},
    {BrowserKind::ChromeCanary, "chrome-canary", "Google Chrome Canary"},
    {BrowserKind::Chromium, "chromium", "Chromium"},
    {BrowserKind::Edge, "edge", "Microsoft Edge"},
    {BrowserKind::EdgeBeta, "edge-beta", "Microsoft Edge Beta"},
    {BrowserKind::EdgeDev, "edge-dev", "Microsoft Edge Dev"},
    {BrowserKind::Brave, "brave", "Brave"},
    {BrowserKind::BraveBeta, "brave-beta", "Brave Beta"},
    {BrowserKind::BraveNightly, "brave-nightly", "Brave Nightly"},
    {BrowserKind::Vivaldi, "vivaldi", "Vivaldi"},
    {BrowserKind::Opera, "opera", "Opera"},
    {BrowserKind::Arc, "arc", "Arc"},
};

const KindInfo& info(BrowserKind kind) {
    for (const KindInfo& k : kKinds) {
        if (k.kind == kind) {
            return k;
        }
    }
    return kKinds[0];
}

}  // namespace

QString browserKindId(BrowserKind kind) {
    return QString::fromLatin1(info(kind).id);
}

QString browserKindName(BrowserKind kind) {
    return QString::fromLatin1(info(kind).name);
}

std::optional<BrowserKind> browserKindFromId(QStringView id) {
    for (const KindInfo& k : kKinds) {
        if (id.compare(QLatin1StringView(k.id), Qt::CaseInsensitive) == 0) {
            return k.kind;
        }
    }
    return std::nullopt;
}

QList<BrowserInstall> knownBrowserLocations() {
    using enum BrowserKind;
    QList<BrowserInstall> out;
    auto add = [&out](BrowserKind kind, const QString& path) {
        if (!path.isEmpty()) {
            out.append({kind, browserKindName(kind), QDir::cleanPath(path)});
        }
    };
    const QString home = QDir::homePath();

#if defined(Q_OS_MACOS)
    const QString base = home + QStringLiteral("/Library/Application Support/");
    add(Chrome, base + QStringLiteral("Google/Chrome"));
    add(ChromeBeta, base + QStringLiteral("Google/Chrome Beta"));
    add(ChromeDev, base + QStringLiteral("Google/Chrome Dev"));
    add(ChromeCanary, base + QStringLiteral("Google/Chrome Canary"));
    add(Chromium, base + QStringLiteral("Chromium"));
    add(Edge, base + QStringLiteral("Microsoft Edge"));
    add(EdgeBeta, base + QStringLiteral("Microsoft Edge Beta"));
    add(EdgeDev, base + QStringLiteral("Microsoft Edge Dev"));
    add(Brave, base + QStringLiteral("BraveSoftware/Brave-Browser"));
    add(BraveBeta, base + QStringLiteral("BraveSoftware/Brave-Browser-Beta"));
    add(BraveNightly, base + QStringLiteral("BraveSoftware/Brave-Browser-Nightly"));
    add(Vivaldi, base + QStringLiteral("Vivaldi"));
    add(Opera, base + QStringLiteral("com.operasoftware.Opera"));
    add(Arc, base + QStringLiteral("Arc/User Data"));
#elif defined(Q_OS_WIN)
    const QString local = QDir::fromNativeSeparators(qEnvironmentVariable("LOCALAPPDATA"));
    const QString roaming = QDir::fromNativeSeparators(qEnvironmentVariable("APPDATA"));
    if (!local.isEmpty()) {
        add(Chrome, local + QStringLiteral("/Google/Chrome/User Data"));
        add(ChromeBeta, local + QStringLiteral("/Google/Chrome Beta/User Data"));
        add(ChromeDev, local + QStringLiteral("/Google/Chrome Dev/User Data"));
        add(ChromeCanary, local + QStringLiteral("/Google/Chrome SxS/User Data"));
        add(Chromium, local + QStringLiteral("/Chromium/User Data"));
        add(Edge, local + QStringLiteral("/Microsoft/Edge/User Data"));
        add(EdgeBeta, local + QStringLiteral("/Microsoft/Edge Beta/User Data"));
        add(EdgeDev, local + QStringLiteral("/Microsoft/Edge Dev/User Data"));
        add(Brave, local + QStringLiteral("/BraveSoftware/Brave-Browser/User Data"));
        add(BraveBeta, local + QStringLiteral("/BraveSoftware/Brave-Browser-Beta/User Data"));
        add(BraveNightly, local + QStringLiteral("/BraveSoftware/Brave-Browser-Nightly/User Data"));
        add(Vivaldi, local + QStringLiteral("/Vivaldi/User Data"));
    }
    if (!roaming.isEmpty()) {
        add(Opera, roaming + QStringLiteral("/Opera Software/Opera Stable"));
    }
#else
    const QString cfg = qEnvironmentVariable("XDG_CONFIG_HOME", home + QStringLiteral("/.config"));
    add(Chrome, cfg + QStringLiteral("/google-chrome"));
    add(ChromeBeta, cfg + QStringLiteral("/google-chrome-beta"));
    add(ChromeDev, cfg + QStringLiteral("/google-chrome-unstable"));
    add(Chromium, cfg + QStringLiteral("/chromium"));
    add(Edge, cfg + QStringLiteral("/microsoft-edge"));
    add(EdgeBeta, cfg + QStringLiteral("/microsoft-edge-beta"));
    add(EdgeDev, cfg + QStringLiteral("/microsoft-edge-dev"));
    add(Brave, cfg + QStringLiteral("/BraveSoftware/Brave-Browser"));
    add(BraveBeta, cfg + QStringLiteral("/BraveSoftware/Brave-Browser-Beta"));
    add(BraveNightly, cfg + QStringLiteral("/BraveSoftware/Brave-Browser-Nightly"));
    add(Vivaldi, cfg + QStringLiteral("/vivaldi"));
    add(Opera, cfg + QStringLiteral("/opera"));
    // Flatpak
    const QString flatpak = home + QStringLiteral("/.var/app/");
    add(Chrome, flatpak + QStringLiteral("com.google.Chrome/config/google-chrome"));
    add(Chromium, flatpak + QStringLiteral("org.chromium.Chromium/config/chromium"));
    add(Edge, flatpak + QStringLiteral("com.microsoft.Edge/config/microsoft-edge"));
    add(Brave, flatpak + QStringLiteral("com.brave.Browser/config/BraveSoftware/Brave-Browser"));
    add(Vivaldi, flatpak + QStringLiteral("com.vivaldi.Vivaldi/config/vivaldi"));
    // Snap
    add(Chromium, home + QStringLiteral("/snap/chromium/common/chromium"));
    add(Brave, home + QStringLiteral("/snap/brave/current/.config/BraveSoftware/Brave-Browser"));
#endif

    // EXTWATCH_USER_DATA_DIRS_ONLY=1 restricts scanning to the directories from the environment
    // (used by demos and tests).
    if (qEnvironmentVariableIsSet("EXTWATCH_USER_DATA_DIRS_ONLY")) {
        return browserLocationsFromEnvironment();
    }
    out += browserLocationsFromEnvironment();
    return out;
}

QList<BrowserInstall> browserLocationsFromEnvironment() {
    QList<BrowserInstall> out;
    const QString env = qEnvironmentVariable("EXTWATCH_USER_DATA_DIRS");
    if (env.isEmpty()) {
        return out;
    }
    for (const QString& item : env.split(u';', Qt::SkipEmptyParts)) {
        const qsizetype eq = item.indexOf(u'=');
        const QString kindId = eq > 0 ? item.left(eq).trimmed() : QStringLiteral("chrome");
        const QString path = (eq > 0 ? item.mid(eq + 1) : item).trimmed();
        const std::optional<BrowserKind> kind = browserKindFromId(kindId);
        if (!kind || path.isEmpty()) {
            continue;
        }
        out.append({*kind, browserKindName(*kind) + QStringLiteral(" (custom)"),
                    QDir::cleanPath(QDir::fromNativeSeparators(path))});
    }
    return out;
}

}  // namespace extwatch
