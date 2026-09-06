#include "cli/cli.h"

#include <QCommandLineParser>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTextStream>
#include <QTimeZone>

#include <QFile>
#include <QJsonArray>
#include <QSet>

#include "core/analyzer.h"
#include "core/blobstore.h"
#include "core/browserkind.h"
#include "core/companion.h"
#include "core/crxid.h"
#include "core/package.h"
#include "core/rules.h"
#include "core/hashing.h"
#include "core/jsonutil.h"
#include "core/signature.h"
#include "core/storemeta.h"
#include "core/textdiff.h"
#include "core/database.h"
#include "core/discovery.h"
#include "core/scanner.h"
#include "extwatch/version.h"

namespace extwatch::cli {

namespace {

const QStringList kCommands = {
    QStringLiteral("scan"),    QStringLiteral("history"), QStringLiteral("paths"),
    QStringLiteral("events"),  QStringLiteral("analyze"), QStringLiteral("diff"),
    QStringLiteral("report"),  QStringLiteral("export"),  QStringLiteral("rules"),
    QStringLiteral("store"),   QStringLiteral("doctor"),  QStringLiteral("help"),
    QStringLiteral("version"),
};

QTextStream& out() {
    static QTextStream stream(stdout);
    return stream;
}

QTextStream& err() {
    static QTextStream stream(stderr);
    return stream;
}

QString usage() {
    return QStringLiteral(
        "ExtWatch %1 - local watchdog for browser extensions\n"
        "\n"
        "Usage: extwatch <command> [options]\n"
        "\n"
        "Commands:\n"
        "  scan                       Inventory every profile, archive new versions, report events\n"
        "  history <id>               Recorded versions and events for one extension id\n"
        "  events                     Most recent events across all extensions\n"
        "  analyze <dir|zip|crx>      Behavior signature and risk profile of any extension package\n"
        "  diff <id> <vA> <vB>        Compare two archived versions (findings, manifest, code)\n"
        "  report <event-id>          Findings and diffs for one recorded event\n"
        "  export <id> <version> <out> Restore an archived version to a directory or .zip\n"
        "  rules                      List the rules behind the findings\n"
        "  store <id>                 Fetch the Web Store listing (publisher, version); uses the network\n"
        "  doctor [--verify-blobs]    Check the database, the archive and the companion for problems\n"
        "\n"
        "Versions can be addressed as 1.2.0, 1.2.0@<tree hash prefix> or @<tree hash prefix> when the\n"
        "same version string was archived more than once.\n"
        "  paths                      Where ExtWatch looks for browsers on this machine\n"
        "  version                    Print the version\n"
        "\n"
        "Run without a command to start the tray app; add --show to open the window right away.\n"
        "\n"
        "Common options:\n"
        "  --json               Machine-readable output\n"
        "  --data-dir <dir>     Database and archive location (default: per-user data dir)\n"
        "  --browser <kind>     Only this browser (chrome, chromium, edge, brave, ...)\n"
        "  --profile <name>     Only this profile (directory or display name)\n"
        "  --user-data-dir <p>  Scan this user data directory (repeatable; use with --browser)\n"
        "  --no-store           Do not write snapshots to the archive\n"
        "  --no-hash            Skip file hashing (implies --no-store)\n"
        "  --no-analyze         Skip signature analysis during scan\n"
        "  --verify             Re-hash every installed tree (scan); default trusts unchanged fingerprints\n"
        "  --html <file>        Write a self-contained HTML report (diff, report)\n"
        "  --full               Do not cap per-file diff output (diff, report)\n"
        "  --compact            Compact JSON\n"
        "\n"
        "Exit codes: 0 ok, 1 error, 2 usage error, 3 a High-severity finding was reported.\n")
        .arg(QStringLiteral(EXTWATCH_VERSION));
}

QString fmtTime(qint64 secs) {
    return QDateTime::fromSecsSinceEpoch(secs, QTimeZone::UTC).toLocalTime().toString(
        QStringLiteral("yyyy-MM-dd HH:mm"));
}

QString pad(const QString& s, int width) {
    if (s.size() >= width) {
        return s.left(width - 1) + QStringLiteral("…");
    }
    return s + QString(width - s.size(), u' ');
}

void printJson(const QJsonObject& obj, bool compact) {
    out() << QString::fromUtf8(QJsonDocument(obj).toJson(compact ? QJsonDocument::Compact
                                                                 : QJsonDocument::Indented))
          << (compact ? "\n" : "");
    out().flush();
}

struct CommonOptions {
    bool json = false;
    bool compact = false;
    QString dataDir;
    std::optional<BrowserKind> browser;
    QString profile;
    QStringList userDataDirs;
    bool store = true;
    bool hash = true;
    bool analyze = true;
    bool verify = false;
    QString html;
    bool full = false;
    bool verifyBlobs = false;
};

bool parseCommon(QCommandLineParser& parser, const QStringList& args, CommonOptions& opts,
                 QString* error) {
    parser.addOptions({
        {QStringLiteral("json"), QStringLiteral("Machine-readable output")},
        {QStringLiteral("compact"), QStringLiteral("Compact JSON")},
        {QStringLiteral("data-dir"), QStringLiteral("Database and archive location"), QStringLiteral("dir")},
        {QStringLiteral("browser"), QStringLiteral("Only this browser kind"), QStringLiteral("kind")},
        {QStringLiteral("profile"), QStringLiteral("Only this profile"), QStringLiteral("name")},
        {QStringLiteral("user-data-dir"), QStringLiteral("Scan this user data directory"), QStringLiteral("path")},
        {QStringLiteral("no-store"), QStringLiteral("Do not write snapshots")},
        {QStringLiteral("no-hash"), QStringLiteral("Skip hashing")},
        {QStringLiteral("no-analyze"), QStringLiteral("Skip analysis")},
        {QStringLiteral("verify"), QStringLiteral("Re-hash every tree instead of trusting stored fingerprints")},
        {QStringLiteral("html"), QStringLiteral("Write HTML report"), QStringLiteral("file")},
        {QStringLiteral("full"), QStringLiteral("Uncapped diff output")},
        {QStringLiteral("verify-blobs"), QStringLiteral("Re-hash every archived blob")},
    });
    parser.addPositionalArgument(QStringLiteral("command"), QString());
    parser.addPositionalArgument(QStringLiteral("args"), QString(), QStringLiteral("[args...]"));
    if (!parser.parse(QStringList(QStringLiteral("extwatch")) + args)) {
        *error = parser.errorText();
        return false;
    }
    opts.json = parser.isSet(QStringLiteral("json"));
    opts.compact = parser.isSet(QStringLiteral("compact"));
    opts.dataDir = parser.value(QStringLiteral("data-dir"));
    if (parser.isSet(QStringLiteral("browser"))) {
        opts.browser = browserKindFromId(parser.value(QStringLiteral("browser")));
        if (!opts.browser) {
            *error = QStringLiteral("unknown browser kind: %1").arg(parser.value(QStringLiteral("browser")));
            return false;
        }
    }
    opts.profile = parser.value(QStringLiteral("profile"));
    opts.userDataDirs = parser.values(QStringLiteral("user-data-dir"));
    opts.store = !parser.isSet(QStringLiteral("no-store"));
    opts.hash = !parser.isSet(QStringLiteral("no-hash"));
    if (!opts.hash) {
        opts.store = false;
    }
    opts.analyze = !parser.isSet(QStringLiteral("no-analyze"));
    opts.verify = parser.isSet(QStringLiteral("verify"));
    opts.html = parser.value(QStringLiteral("html"));
    opts.full = parser.isSet(QStringLiteral("full"));
    opts.verifyBlobs = parser.isSet(QStringLiteral("verify-blobs"));
    return true;
}

ScanOptions toScanOptions(const CommonOptions& c) {
    ScanOptions o;
    o.dataDir = c.dataDir;
    o.persist = c.store;
    o.computeHashes = c.hash;
    o.analyze = c.analyze;
    o.forceHash = c.verify;
    o.onlyBrowser = c.browser;
    o.onlyProfile = c.profile;
    for (const QString& dir : c.userDataDirs) {
        const BrowserKind kind = c.browser.value_or(BrowserKind::Chrome);
        o.candidates.append({kind, browserKindName(kind) + QStringLiteral(" (custom)"),
                             QDir::cleanPath(QFileInfo(dir).absoluteFilePath())});
    }
    if (!o.candidates.isEmpty()) {
        o.onlyBrowser.reset();  // custom dirs already select the browser
    }
    return o;
}

int cmdScan(const CommonOptions& c) {
    const ScanResult result = runScan(toScanOptions(c));
    if (c.json) {
        printJson(result.toJson(), c.compact);
        return scanExitCode(result);
    }
    for (const BrowserReport& b : result.browsers) {
        for (const ProfileReport& p : b.profiles) {
            out() << b.install.displayName << " · " << p.profile.dirName;
            if (p.profile.displayName != p.profile.dirName) {
                out() << " (" << p.profile.displayName << ")";
            }
            out() << " · " << p.extensions.size() << " extension"
                  << (p.extensions.size() == 1 ? "" : "s") << "\n";
            for (const ExtensionReport& e : p.extensions) {
                out() << "  " << (e.enabled ? "[on ] " : "[off] ") << pad(e.name, 36)
                      << pad(e.activeVersion, 12) << e.id << "  "
                      << (e.fromWebstore ? QStringLiteral("webstore") : e.locationId);
                if (!e.disableReasons.isEmpty()) {
                    out() << "  (" << e.disableReasons.join(QStringLiteral(", ")) << ")";
                }
                if (e.versions.size() > 1) {
                    out() << "  +" << (e.versions.size() - 1) << " other version dir"
                          << (e.versions.size() > 2 ? "s" : "");
                }
                for (const VersionReport& v : e.versions) {
                    if (!v.keyMatchesId) {
                        out() << "  KEY MISMATCH";
                        break;
                    }
                }
                out() << "\n";
                for (const QString& note : e.notes) {
                    out() << "        note: " << note << "\n";
                }
            }
            for (const QString& w : p.warnings) {
                out() << "  warning: " << w << "\n";
            }
            out() << "\n";
        }
    }
    if (result.browsers.isEmpty()) {
        out() << "No Chrome-family browser profiles found. Use --user-data-dir or set"
                 " EXTWATCH_USER_DATA_DIRS.\n";
    }
    QHash<QString, int> kinds;
    for (const ScanEvent& e : result.events) {
        kinds[e.kind]++;
        if (e.kind != QStringLiteral("baseline")) {
            out() << "event";
            if (!e.maxSeverity.isEmpty()) {
                out() << " [" << e.maxSeverity.toUpper() << "]";
            }
            out() << ": " << e.summary() << "  (" << e.browserName << " / " << e.profileName << ")\n";
        }
    }
    QStringList parts;
    for (auto it = kinds.cbegin(); it != kinds.cend(); ++it) {
        parts.append(QStringLiteral("%1 %2").arg(it.value()).arg(it.key()));
    }
    out() << result.extensionCount() << " extensions in " << result.profileCount() << " profiles";
    if (!parts.isEmpty()) {
        out() << "; events: " << parts.join(QStringLiteral(", "));
    }
    out() << "\n";
    if (!result.dataDir.isEmpty()) {
        out() << "archive: " << result.dataDir << "\n";
    }
    for (const QString& w : result.warnings) {
        err() << "warning: " << w << "\n";
    }
    out().flush();
    err().flush();
    return scanExitCode(result);
}

QString locate(Database& db, const ExtensionRow& ext) {
    const std::optional<ProfileRow> profile = db.profileById(ext.profileId);
    const std::optional<BrowserRow> browser =
        profile ? db.browserById(profile->browserId) : std::nullopt;
    return QStringLiteral("%1 / %2")
        .arg(browser ? browser->displayName : QStringLiteral("?"),
             profile ? profile->displayName : QStringLiteral("?"));
}

QJsonObject versionRowToJson(const VersionRow& v) {
    QJsonObject o;
    o.insert(QStringLiteral("id"), v.id);
    o.insert(QStringLiteral("version"), v.version);
    o.insert(QStringLiteral("dir"), v.dirName);
    o.insert(QStringLiteral("tree_hash"), QStringLiteral("sha256:") + v.treeHash);
    o.insert(QStringLiteral("first_seen"), QDateTime::fromSecsSinceEpoch(v.firstSeen, QTimeZone::UTC).toString(Qt::ISODate));
    o.insert(QStringLiteral("last_seen"), QDateTime::fromSecsSinceEpoch(v.lastSeen, QTimeZone::UTC).toString(Qt::ISODate));
    if (v.activatedAt) {
        o.insert(QStringLiteral("activated_at"), QDateTime::fromSecsSinceEpoch(*v.activatedAt, QTimeZone::UTC).toString(Qt::ISODate));
    }
    o.insert(QStringLiteral("files"), v.fileCount);
    o.insert(QStringLiteral("bytes"), v.bytes);
    o.insert(QStringLiteral("key_matches_id"), v.keyMatchesId);
    o.insert(QStringLiteral("has_webstore_metadata"), v.hasWebstoreMetadata);
    return o;
}

QJsonObject eventRowToJson(Database& db, const EventRow& e) {
    QJsonObject o;
    o.insert(QStringLiteral("id"), e.id);
    o.insert(QStringLiteral("kind"), e.kind);
    o.insert(QStringLiteral("at"), QDateTime::fromSecsSinceEpoch(e.at, QTimeZone::UTC).toString(Qt::ISODate));
    if (e.fromVersionId) {
        if (const auto v = db.versionById(*e.fromVersionId)) {
            o.insert(QStringLiteral("from_version"), v->version);
        }
    }
    if (e.toVersionId) {
        if (const auto v = db.versionById(*e.toVersionId)) {
            o.insert(QStringLiteral("to_version"), v->version);
        }
    }
    if (!e.maxSeverity.isEmpty()) {
        o.insert(QStringLiteral("max_severity"), e.maxSeverity);
    }
    if (!e.findingsJson.isEmpty()) {
        o.insert(QStringLiteral("findings"), QJsonDocument::fromJson(e.findingsJson.toUtf8()).array());
    }
    o.insert(QStringLiteral("acknowledged"), e.acknowledged);
    return o;
}

int cmdHistory(const CommonOptions& c, const QStringList& positional) {
    if (positional.size() < 2) {
        err() << "usage: extwatch history <extension-id>\n";
        return 2;
    }
    const QString extId = positional.at(1);
    Database db;
    QString error;
    const QString dataDir = c.dataDir.isEmpty() ? defaultDataDir() : c.dataDir;
    if (!db.open(databasePath(dataDir), &error)) {
        err() << "cannot open database: " << error << "\n";
        return 1;
    }
    const QList<ExtensionRow> rows = db.extensionsByExtId(extId);
    if (rows.isEmpty()) {
        err() << "no records for " << extId << " (run `extwatch scan` first)\n";
        return 1;
    }
    QJsonArray jsonRows;
    for (const ExtensionRow& ext : rows) {
        const QList<VersionRow> versions = db.versionsForExtension(ext.id);
        const QList<EventRow> events = db.eventsForExtension(ext.id);
        if (c.json) {
            QJsonObject o;
            o.insert(QStringLiteral("id"), ext.extId);
            o.insert(QStringLiteral("name"), ext.name);
            o.insert(QStringLiteral("where"), locate(db, ext));
            o.insert(QStringLiteral("enabled"), ext.enabled);
            QJsonArray vs;
            for (const VersionRow& v : versions) {
                QJsonObject vo = versionRowToJson(v);
                vo.insert(QStringLiteral("current"), ext.currentVersionId && *ext.currentVersionId == v.id);
                vs.append(vo);
            }
            o.insert(QStringLiteral("versions"), vs);
            QJsonArray es;
            for (const EventRow& e : events) {
                es.append(eventRowToJson(db, e));
            }
            o.insert(QStringLiteral("events"), es);
            jsonRows.append(o);
            continue;
        }
        out() << ext.name << " (" << ext.extId << ") · " << locate(db, ext) << " · "
              << (ext.enabled ? "enabled" : "disabled") << "\n";
        out() << "  versions:\n";
        for (const VersionRow& v : versions) {
            const bool current = ext.currentVersionId && *ext.currentVersionId == v.id;
            out() << "    " << (current ? "* " : "  ") << pad(v.version + QStringLiteral("@") + v.treeHash.left(8), 24)
                  << "first seen " << fmtTime(v.firstSeen) << "  " << v.fileCount << " files, "
                  << v.bytes / 1024 << " KiB\n";
        }
        out() << "  events:\n";
        for (const EventRow& e : events) {
            out() << "    " << fmtTime(e.at) << "  " << pad(e.kind, 16);
            if (e.fromVersionId) {
                if (const auto v = db.versionById(*e.fromVersionId)) {
                    out() << v->version << " → ";
                }
            }
            if (e.toVersionId) {
                if (const auto v = db.versionById(*e.toVersionId)) {
                    out() << v->version;
                }
            }
            if (!e.maxSeverity.isEmpty()) {
                out() << "  [" << e.maxSeverity << "]";
            }
            out() << "\n";
        }
        out() << "\n";
    }
    if (c.json) {
        QJsonObject root;
        root.insert(QStringLiteral("extensions"), jsonRows);
        printJson(root, c.compact);
    }
    out().flush();
    return 0;
}

int cmdEvents(const CommonOptions& c) {
    Database db;
    QString error;
    const QString dataDir = c.dataDir.isEmpty() ? defaultDataDir() : c.dataDir;
    if (!db.open(databasePath(dataDir), &error)) {
        err() << "cannot open database: " << error << "\n";
        return 1;
    }
    const QList<EventRow> events = db.recentEvents(50);
    QJsonArray arr;
    for (const EventRow& e : events) {
        const std::optional<ExtensionRow> ext = db.extensionById(e.extensionId);
        if (c.json) {
            QJsonObject o = eventRowToJson(db, e);
            if (ext) {
                o.insert(QStringLiteral("extension"), ext->extId);
                o.insert(QStringLiteral("name"), ext->name);
                o.insert(QStringLiteral("where"), locate(db, *ext));
            }
            arr.append(o);
            continue;
        }
        out() << fmtTime(e.at) << "  " << pad(e.kind, 16) << pad(ext ? ext->name : QString(), 32);
        if (e.fromVersionId) {
            if (const auto v = db.versionById(*e.fromVersionId)) {
                out() << v->version << " → ";
            }
        }
        if (e.toVersionId) {
            if (const auto v = db.versionById(*e.toVersionId)) {
                out() << v->version;
            }
        }
        if (!e.maxSeverity.isEmpty()) {
            out() << "  [" << e.maxSeverity << "]";
        }
        if (ext) {
            out() << "  " << locate(db, *ext);
        }
        out() << "\n";
    }
    if (c.json) {
        QJsonObject root;
        root.insert(QStringLiteral("events"), arr);
        printJson(root, c.compact);
    }
    out().flush();
    return 0;
}

int cmdPaths(const CommonOptions& c) {
    QJsonArray arr;
    for (const BrowserInstall& b : knownBrowserLocations()) {
        const bool exists = QFileInfo(b.userDataDir).isDir();
        const QList<Profile> profiles = exists ? discoverProfiles(b.userDataDir) : QList<Profile>();
        if (c.json) {
            QJsonObject o;
            o.insert(QStringLiteral("kind"), browserKindId(b.kind));
            o.insert(QStringLiteral("name"), b.displayName);
            o.insert(QStringLiteral("user_data_dir"), b.userDataDir);
            o.insert(QStringLiteral("exists"), exists);
            QJsonArray ps;
            for (const Profile& p : profiles) {
                QJsonObject po;
                po.insert(QStringLiteral("dir"), p.dirName);
                po.insert(QStringLiteral("name"), p.displayName);
                ps.append(po);
            }
            o.insert(QStringLiteral("profiles"), ps);
            arr.append(o);
            continue;
        }
        out() << (exists ? "[found]   " : "[absent]  ") << pad(b.displayName, 26) << b.userDataDir;
        if (exists) {
            out() << "  (" << profiles.size() << " profile" << (profiles.size() == 1 ? "" : "s") << ")";
        }
        out() << "\n";
    }
    if (c.json) {
        QJsonObject root;
        root.insert(QStringLiteral("locations"), arr);
        printJson(root, c.compact);
    }
    out().flush();
    return 0;
}


QString severityTag(Severity s) {
    return QStringLiteral("[%1]").arg(severityId(s).toUpper());
}

void printFindings(const QList<Finding>& findings) {
    if (findings.isEmpty()) {
        out() << "  (no findings)\n";
        return;
    }
    for (const Finding& f : findings) {
        out() << "  " << pad(severityTag(f.severity), 9) << f.title;
        if (!f.file.isEmpty()) {
            out() << "  (" << f.file << (f.line > 0 ? QStringLiteral(":%1").arg(f.line) : QString()) << ")";
        }
        out() << "\n           " << f.detail << "\n";
    }
}

int exitCodeFor(const QList<Finding>& findings) {
    return maxSeverity(findings) == Severity::High ? 3 : 0;
}

int cmdAnalyze(const CommonOptions& c, const QStringList& positional) {
    if (positional.size() < 2) {
        err() << "usage: extwatch analyze <dir|zip|crx>\n";
        return 2;
    }
    QString error;
    QStringList packageWarnings;
    const QList<SourceFile> files = loadSourcesFromPackage(positional.at(1), &error, &packageWarnings);
    for (const QString& w : packageWarnings) {
        err() << "warning: " << w << "\n";
    }
    err().flush();
    if (files.isEmpty()) {
        err() << "cannot read package: " << (error.isEmpty() ? QStringLiteral("no files") : error) << "\n";
        return 1;
    }
    ManifestFacts manifest;
    QJsonObject messages;
    for (const SourceFile& f : files) {
        if (f.path == QStringLiteral("manifest.json")) {
            const QJsonObject obj = QJsonDocument::fromJson(f.content).object();
            const QString locale = obj.value(QStringLiteral("default_locale")).toString();
            for (const SourceFile& m : files) {
                if (!locale.isEmpty() && m.path == QStringLiteral("_locales/%1/messages.json").arg(locale)) {
                    messages = QJsonDocument::fromJson(m.content).object();
                }
            }
            manifest = parseManifest(obj, [&messages](const QString& s) { return resolveI18n(s, messages); });
        }
    }
    if (!manifest.valid) {
        err() << "package has no manifest.json\n";
        return 1;
    }
    const QString expectedId = manifest.key.isEmpty() ? QString() : extensionIdFromManifestKey(manifest.key);
    Signature sig = buildSignature(manifest, files, expectedId);
    const QList<Finding> findings = compareSignatures(Signature(), sig);
    if (c.json) {
        QJsonObject root;
        root.insert(QStringLiteral("extwatch"), QStringLiteral(EXTWATCH_VERSION));
        root.insert(QStringLiteral("package"), positional.at(1));
        root.insert(QStringLiteral("id_from_key"), expectedId);
        root.insert(QStringLiteral("signature"), sig.toJson());
        root.insert(QStringLiteral("findings"), findingsToJson(findings));
        root.insert(QStringLiteral("max_severity"), severityId(maxSeverity(findings)));
        printJson(root, c.compact);
        return exitCodeFor(findings);
    }
    out() << manifest.name << " " << manifest.version << " (manifest v" << manifest.manifestVersion << ")";
    if (!expectedId.isEmpty()) {
        out() << "  id " << expectedId;
    }
    out() << "\n  " << files.size() << " files, " << sig.totalBytes / 1024 << " KiB; "
          << sig.domains.size() << " domains, " << sig.sinks.size() << " sinks, "
          << sig.chromeApis.size() << " chrome.* APIs\n";
    if (!sig.manifest.hostPermissions.isEmpty()) {
        out() << "  hosts: " << sig.manifest.hostPermissions.join(QStringLiteral(", ")) << "\n";
    }
    if (!sig.manifest.permissions.isEmpty()) {
        out() << "  permissions: " << sig.manifest.permissions.join(QStringLiteral(", ")) << "\n";
    }
    if (!sig.domains.isEmpty()) {
        out() << "  domains: " << sig.domainHosts().join(QStringLiteral(", ")) << "\n";
    }
    out() << "\nRisk profile:\n";
    printFindings(findings);
    out().flush();
    return exitCodeFor(findings);
}

void printReport(Database& db, const BlobStore& blobs, const ChangeReport& r, bool full) {
    out() << r.name << " (" << r.extId << ")";
    if (!r.browserName.isEmpty()) {
        out() << " · " << r.browserName << " / " << r.profileName;
    }
    out() << "\n" << (r.from ? r.from->version : QStringLiteral("(none)")) << " → " << r.to.version
          << "   tree " << (r.from ? r.from->treeHash.left(12) : QStringLiteral("-")) << " → " << r.to.treeHash.left(12) << "\n\n";
    out() << "Findings (" << severityId(maxSeverity(r.findings)).toUpper() << "):\n";
    printFindings(r.findings);
    out() << "\nFiles:\n";
    for (const FileChange& f : r.files) {
        if (f.status == FileChange::Status::Unchanged) {
            continue;
        }
        const char* st = f.status == FileChange::Status::Modified ? "modified" : f.status == FileChange::Status::Added ? "added   " : "removed ";
        out() << "  " << st << "  " << f.path << "  (" << f.oldBytes << " → " << f.newBytes << " bytes)\n";
    }
    if (r.manifestDiff.count(u'\n') > 2) {
        out() << "\nManifest diff:\n" << r.manifestDiff;
    }
    for (const FileChange& f : r.files) {
        if (f.status == FileChange::Status::Unchanged || f.path == QStringLiteral("manifest.json")) {
            continue;
        }
        const std::optional<QString> oldText = r.from ? fileDisplayText(db, blobs, r.from->id, f.path) : std::nullopt;
        const std::optional<QString> newText = fileDisplayText(db, blobs, r.to.id, f.path);
        if ((oldText && oldText->startsWith(QStringLiteral("[binary"))) || (newText && newText->startsWith(QStringLiteral("[binary")))) {
            continue;
        }
        const LineDiff diff = diffLines(oldText ? splitLines(*oldText) : QStringList(), newText ? splitLines(*newText) : QStringList());
        if (diff.truncated) {
            out() << "\n" << f.path << ": too large to diff\n";
            continue;
        }
        QList<Hunk> hunks = hunksFromDiff(diff, 3);
        int lines = 0;
        QList<Hunk> shown;
        for (const Hunk& h : hunks) {
            if (!full && lines + h.lines.size() > 200) {
                break;
            }
            lines += static_cast<int>(h.lines.size());
            shown.append(h);
        }
        out() << "\n" << unifiedDiff(QStringLiteral("a/") + f.path, QStringLiteral("b/") + f.path, shown);
        if (shown.size() < hunks.size()) {
            out() << "... " << (hunks.size() - shown.size()) << " more hunks (use --full)\n";
        }
    }
    out().flush();
}

QJsonObject reportToJson(const ChangeReport& r) {
    QJsonObject o;
    o.insert(QStringLiteral("id"), r.extId);
    o.insert(QStringLiteral("name"), r.name);
    o.insert(QStringLiteral("browser"), r.browserName);
    o.insert(QStringLiteral("profile"), r.profileName);
    o.insert(QStringLiteral("event"), r.eventKind);
    if (r.from) {
        o.insert(QStringLiteral("from_version"), r.from->version);
        o.insert(QStringLiteral("from_tree_hash"), QStringLiteral("sha256:") + r.from->treeHash);
    }
    o.insert(QStringLiteral("to_version"), r.to.version);
    o.insert(QStringLiteral("to_tree_hash"), QStringLiteral("sha256:") + r.to.treeHash);
    o.insert(QStringLiteral("max_severity"), severityId(maxSeverity(r.findings)));
    o.insert(QStringLiteral("findings"), findingsToJson(r.findings));
    QJsonArray files;
    for (const FileChange& f : r.files) {
        if (f.status == FileChange::Status::Unchanged) {
            continue;
        }
        QJsonObject fo;
        fo.insert(QStringLiteral("path"), f.path);
        fo.insert(QStringLiteral("status"), f.status == FileChange::Status::Modified ? QStringLiteral("modified") : f.status == FileChange::Status::Added ? QStringLiteral("added") : QStringLiteral("removed"));
        fo.insert(QStringLiteral("old_bytes"), f.oldBytes);
        fo.insert(QStringLiteral("new_bytes"), f.newBytes);
        files.append(fo);
    }
    o.insert(QStringLiteral("files"), files);
    o.insert(QStringLiteral("manifest_diff"), r.manifestDiff);
    o.insert(QStringLiteral("to_signature"), r.toSignature.toJson());
    return o;
}

int emitReport(const CommonOptions& c, Database& db, const BlobStore& blobs, const ChangeReport& r) {
    if (!c.html.isEmpty()) {
        QFile f(c.html);
        if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            err() << "cannot write " << c.html << "\n";
            return 1;
        }
        f.write(renderHtmlReport(db, blobs, r, c.full ? 1000 : 25, c.full ? 100000 : 600).toUtf8());
        out() << "wrote " << c.html << "\n";
    }
    if (c.json) {
        printJson(reportToJson(r), c.compact);
    } else if (c.html.isEmpty()) {
        printReport(db, blobs, r, c.full);
    }
    out().flush();
    return exitCodeFor(r.findings);
}

bool openStore(const CommonOptions& c, Database& db, QString& dataDir) {
    dataDir = c.dataDir.isEmpty() ? defaultDataDir() : c.dataDir;
    QString error;
    if (!db.open(databasePath(dataDir), &error)) {
        err() << "cannot open database: " << error << "\n";
        return false;
    }
    return true;
}

int cmdDiff(const CommonOptions& c, const QStringList& positional) {
    if (positional.size() < 4) {
        err() << "usage: extwatch diff <extension-id> <old-version> <new-version> [--json] [--html out.html]\n";
        return 2;
    }
    Database db;
    QString dataDir;
    if (!openStore(c, db, dataDir)) {
        return 1;
    }
    const BlobStore blobs(dataDir);
    const QString extId = positional.at(1);
    const QString vA = positional.at(2);
    const QString vB = positional.at(3);
    for (const ExtensionRow& ext : db.extensionsByExtId(extId)) {
        if (!c.profile.isEmpty()) {
            const std::optional<ProfileRow> p = db.profileById(ext.profileId);
            if (!p || (p->dirName != c.profile && p->displayName != c.profile)) {
                continue;
            }
        }
        QString note;
        const std::optional<VersionRow> rowA = vA == QStringLiteral("none") ? std::nullopt : resolveVersionRef(db, ext.id, vA, &note);
        const std::optional<VersionRow> rowB = resolveVersionRef(db, ext.id, vB, &note);
        if (!rowB || (!rowA && vA != QStringLiteral("none"))) {
            continue;
        }
        if (!note.isEmpty()) {
            err() << "note: " << note << "\n";
            err().flush();
        }
        const std::optional<ChangeReport> r = buildVersionReport(db, blobs, rowA ? std::optional<qint64>(rowA->id) : std::nullopt, rowB->id);
        if (!r) {
            continue;
        }
        return emitReport(c, db, blobs, *r);
    }
    err() << "no archived versions " << vA << " and " << vB << " for " << extId << " (see `extwatch history`)\n";
    return 1;
}

int cmdReport(const CommonOptions& c, const QStringList& positional) {
    if (positional.size() < 2) {
        err() << "usage: extwatch report <event-id> [--json] [--html out.html]\n";
        return 2;
    }
    Database db;
    QString dataDir;
    if (!openStore(c, db, dataDir)) {
        return 1;
    }
    const BlobStore blobs(dataDir);
    const std::optional<ChangeReport> r = buildChangeReport(db, blobs, positional.at(1).toLongLong());
    if (!r) {
        err() << "no such event with a version: " << positional.at(1) << " (see `extwatch events`)\n";
        return 1;
    }
    return emitReport(c, db, blobs, *r);
}

int cmdExport(const CommonOptions& c, const QStringList& positional) {
    if (positional.size() < 4) {
        err() << "usage: extwatch export <extension-id> <version> <out-dir|out.zip>\n";
        return 2;
    }
    Database db;
    QString dataDir;
    if (!openStore(c, db, dataDir)) {
        return 1;
    }
    const BlobStore blobs(dataDir);
    for (const ExtensionRow& ext : db.extensionsByExtId(positional.at(1))) {
        QString note;
        const std::optional<VersionRow> resolved = resolveVersionRef(db, ext.id, positional.at(2), &note);
        if (!resolved) {
            continue;
        }
        if (!note.isEmpty()) {
            err() << "note: " << note << "\n";
        }
        {
            const VersionRow& v = *resolved;
            const QString target = positional.at(3);
            QString error;
            bool ok = false;
            if (target.endsWith(QStringLiteral(".zip"), Qt::CaseInsensitive)) {
                ok = writeZip(target, loadSourcesFromArchive(db, blobs, v.id), &error);
            } else {
                ok = blobs.exportTree(db.filesForVersion(v.id), target, &error);
            }
            if (!ok) {
                err() << "export failed: " << error << "\n";
                return 1;
            }
            out() << "exported " << ext.name << " " << v.version << "@" << v.treeHash.left(12) << " (" << v.fileCount << " files) to " << target << "\n";
            out() << "To run it: disable the store copy, open chrome://extensions, enable Developer mode, Load unpacked.\n";
            out().flush();
            return 0;
        }
    }
    err() << "no archived version " << positional.at(2) << " for " << positional.at(1) << "\n";
    return 1;
}

int cmdDoctor(const CommonOptions& c) {
    Database db;
    QString dataDir;
    if (!openStore(c, db, dataDir)) {
        return 1;
    }
    const BlobStore blobs(dataDir);
    QStringList problems;
    QJsonObject report;
    report.insert(QStringLiteral("data_dir"), dataDir);
    report.insert(QStringLiteral("schema_version"), db.schemaVersion());

    QString check;
    const bool dbOk = db.quickCheck(&check);
    report.insert(QStringLiteral("sqlite_quick_check"), check);
    if (!dbOk) problems.append(QStringLiteral("SQLite quick_check: %1").arg(check));

    int versions = 0, filesChecked = 0, missingBlobs = 0, badBlobs = 0, countMismatch = 0;
    QSet<QString> referenced;
    for (const VersionRow& v : db.allVersions()) {
        versions++;
        const QList<FileEntry> files = db.filesForVersion(v.id);
        if (files.size() != v.fileCount) {
            countMismatch++;
            problems.append(QStringLiteral("snapshot %1 (%2) records %3 files but has %4 rows").arg(v.id).arg(v.version).arg(v.fileCount).arg(files.size()));
        }
        for (const FileEntry& f : files) {
            filesChecked++;
            referenced.insert(toHex(f.sha256));
            if (!blobs.has(f.sha256)) {
                missingBlobs++;
                if (missingBlobs <= 5) problems.append(QStringLiteral("missing blob for %1 in snapshot %2").arg(f.relPath).arg(v.id));
            } else if (c.verifyBlobs && !blobs.verify(f.sha256)) {
                badBlobs++;
                problems.append(QStringLiteral("blob content does not match its hash: %1 (%2)").arg(toHex(f.sha256).left(12), f.relPath));
            }
        }
    }
    int orphans = 0;
    for (const QByteArray& sha : blobs.allBlobs()) {
        if (!referenced.contains(toHex(sha))) orphans++;
    }
    report.insert(QStringLiteral("snapshots"), versions);
    report.insert(QStringLiteral("file_rows"), filesChecked);
    report.insert(QStringLiteral("missing_blobs"), missingBlobs);
    report.insert(QStringLiteral("bad_blobs"), badBlobs);
    report.insert(QStringLiteral("orphan_blobs"), orphans);
    report.insert(QStringLiteral("blobs_verified"), c.verifyBlobs);

    const int unanalyzed = static_cast<int>(db.unanalyzedEvents(1000).size());
    report.insert(QStringLiteral("events_without_findings"), unanalyzed);
    if (unanalyzed > 0) problems.append(QStringLiteral("%1 event(s) have no findings yet; the next scan analyzes them").arg(unanalyzed));

    int quarantineIssues = 0;
    for (const QuarantineRow& q : db.allQuarantines()) {
        if (q.state != QStringLiteral("restored") && !QFileInfo(q.quarantinePath).isDir()) {
            quarantineIssues++;
            problems.append(QStringLiteral("quarantine %1 (%2) is missing on disk").arg(q.id.left(8), q.extId));
        }
    }
    report.insert(QStringLiteral("quarantine_issues"), quarantineIssues);

    if (companionExtracted(dataDir)) {
        const bool intact = companionExtractedHash(dataDir) == companionEmbeddedHash();
        report.insert(QStringLiteral("companion_intact"), intact);
        if (!intact) problems.append(QStringLiteral("the extracted companion extension differs from the embedded one"));
    }
#ifndef Q_OS_WIN
    const QFileDevice::Permissions perms = QFileInfo(dataDir).permissions();
    const bool privateDir = !(perms & (QFileDevice::ReadGroup | QFileDevice::ReadOther));
    report.insert(QStringLiteral("data_dir_private"), privateDir);
    if (!privateDir) problems.append(QStringLiteral("data directory is readable by other users: chmod 700 \"%1\"").arg(dataDir));
#endif
    report.insert(QStringLiteral("problems"), fromStringList(problems));
    if (c.json) {
        printJson(report, c.compact);
        return problems.isEmpty() ? 0 : 1;
    }
    out() << "archive:        " << dataDir << "\n"
          << "schema:         " << db.schemaVersion() << "\n"
          << "sqlite:         " << check << "\n"
          << "snapshots:      " << versions << " (" << filesChecked << " file rows, " << countMismatch << " count mismatches)\n"
          << "blobs:          " << missingBlobs << " missing, " << badBlobs << " corrupt" << (c.verifyBlobs ? QString() : QStringLiteral(" (not verified; add --verify-blobs)")) << ", " << orphans << " orphaned\n"
          << "events:         " << unanalyzed << " without findings\n";
    if (problems.isEmpty()) {
        out() << "\nno problems found\n";
    } else {
        out() << "\nproblems:\n";
        for (const QString& p : problems) out() << "  - " << p << "\n";
    }
    out().flush();
    return problems.isEmpty() ? 0 : 1;
}

int cmdStore(const CommonOptions& c, const QStringList& positional) {
    if (positional.size() < 2) {
        err() << "usage: extwatch store <extension-id>\n";
        return 2;
    }
    const StoreListing l = fetchStoreListing(positional.at(1));
    const UpdateCheck u = fetchUpdateCheck(positional.at(1));
    if (c.json) {
        QJsonObject root = l.toJson();
        root.insert(QStringLiteral("update_check_version"), u.ok ? u.version : QString());
        printJson(root, c.compact);
        return l.found ? 0 : 1;
    }
    if (!l.found) {
        out() << (l.gone ? "no Chrome Web Store listing with this ID" : "could not read the Chrome Web Store listing")
              << " (HTTP " << l.httpStatus << ")";
        if (!l.error.isEmpty()) out() << ": " << l.error;
        out() << "\n";
        out().flush();
        return 1;
    }
    out() << l.name << "\n  offered by:  " << l.developer << (l.developerEmail.isEmpty() ? QString() : QStringLiteral(" <%1>").arg(l.developerEmail)) << "\n"
          << "  version:     " << l.version << (u.ok && u.version != l.version ? QStringLiteral("  (update server says %1)").arg(u.version) : QString()) << "\n"
          << "  updated:     " << l.updated << "\n  size:        " << l.size << "\n  rating:      " << l.rating
          << (l.users.isEmpty() ? QString() : QStringLiteral("  (%1 users)").arg(l.users)) << "\n  trader:      " << l.traderStatus << "\n";
    out().flush();
    return 0;
}

int cmdRules(const CommonOptions& c) {
    if (c.json) {
        QJsonArray arr;
        for (const RuleInfo& r : allRules()) {
            QJsonObject o;
            o.insert(QStringLiteral("id"), r.id);
            o.insert(QStringLiteral("severity"), severityId(r.severity));
            o.insert(QStringLiteral("title"), r.title);
            o.insert(QStringLiteral("explanation"), r.explanation);
            arr.append(o);
        }
        QJsonObject root;
        root.insert(QStringLiteral("schema"), 1);
        root.insert(QStringLiteral("extwatch"), QStringLiteral(EXTWATCH_VERSION));
        root.insert(QStringLiteral("rules"), arr);
        printJson(root, c.compact);
        return 0;
    }
    for (const RuleInfo& r : allRules()) {
        out() << pad(severityTag(r.severity), 9) << pad(r.id, 36) << r.title << "\n           " << r.explanation << "\n";
    }
    out().flush();
    return 0;
}

}  // namespace

bool wantsCli(const QStringList& args) {
    if (args.isEmpty()) {
        return false;
    }
    const QString first = args.first();
    return kCommands.contains(first) || first == QStringLiteral("--help") ||
           first == QStringLiteral("-h") || first == QStringLiteral("--version") ||
           first == QStringLiteral("-v");
}

int run(const QStringList& args) {
    if (args.isEmpty() || args.first() == QStringLiteral("help") ||
        args.first() == QStringLiteral("--help") || args.first() == QStringLiteral("-h")) {
        out() << usage();
        out().flush();
        return 0;
    }
    if (args.first() == QStringLiteral("version") || args.first() == QStringLiteral("--version") ||
        args.first() == QStringLiteral("-v")) {
        out() << "extwatch " << EXTWATCH_VERSION << "\n";
        out().flush();
        return 0;
    }
    QCommandLineParser parser;
    CommonOptions common;
    QString error;
    if (!parseCommon(parser, args, common, &error)) {
        err() << "error: " << error << "\n\n" << usage();
        err().flush();
        return 2;
    }
    const QStringList positional = parser.positionalArguments();
    const QString command = positional.value(0);
    if (command == QStringLiteral("scan")) {
        return cmdScan(common);
    }
    if (command == QStringLiteral("history")) {
        return cmdHistory(common, positional);
    }
    if (command == QStringLiteral("events")) {
        return cmdEvents(common);
    }
    if (command == QStringLiteral("paths")) {
        return cmdPaths(common);
    }
    if (command == QStringLiteral("analyze")) {
        return cmdAnalyze(common, positional);
    }
    if (command == QStringLiteral("diff")) {
        return cmdDiff(common, positional);
    }
    if (command == QStringLiteral("report")) {
        return cmdReport(common, positional);
    }
    if (command == QStringLiteral("export")) {
        return cmdExport(common, positional);
    }
    if (command == QStringLiteral("rules")) {
        return cmdRules(common);
    }
    if (command == QStringLiteral("store")) {
        return cmdStore(common, positional);
    }
    if (command == QStringLiteral("doctor")) {
        return cmdDoctor(common);
    }
    err() << "unknown command: " << command << "\n\n" << usage();
    err().flush();
    return 2;
}

}  // namespace extwatch::cli
