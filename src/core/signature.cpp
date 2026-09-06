#include "core/signature.h"

#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QSet>
#include <QtConcurrent/QtConcurrent>
#include <algorithm>

#include "core/crxid.h"
#include "core/jsonutil.h"
#include "core/prettify.h"

namespace extwatch {

QStringList Signature::domainHosts() const {
    QStringList out;
    for (const DomainRef& d : domains) {
        out.append(d.host);
    }
    return out;
}

bool Signature::hasSink(const QString& kind) const {
    return std::any_of(sinks.begin(), sinks.end(), [&](const Sink& s) { return s.kind == kind; });
}

QList<Sink> Signature::sinksOfKind(const QString& kind) const {
    QList<Sink> out;
    for (const Sink& s : sinks) {
        if (s.kind == kind) {
            out.append(s);
        }
    }
    return out;
}

QList<Sink> Signature::sinksInFile(const QString& file) const {
    QList<Sink> out;
    for (const Sink& s : sinks) {
        if (s.file == file) {
            out.append(s);
        }
    }
    return out;
}

QList<SourceFile> loadSourcesFromDir(const QString& dir) {
    QList<SourceFile> out;
    const QDir root(dir);
    QDirIterator it(dir, QDir::Files | QDir::Hidden | QDir::NoSymLinks | QDir::NoDotAndDotDot,
                    QDirIterator::Subdirectories);
    while (it.hasNext()) {
        const QFileInfo fi = it.nextFileInfo();
        QFile f(fi.filePath());
        if (!f.open(QIODevice::ReadOnly)) {
            continue;
        }
        out.append({root.relativeFilePath(fi.filePath()), f.readAll()});
    }
    std::sort(out.begin(), out.end(),
              [](const SourceFile& a, const SourceFile& b) { return a.path < b.path; });
    return out;
}

namespace {

const QSet<QString>& securityHeaders() {
    static const QSet<QString> headers = {
        QStringLiteral("content-security-policy"),
        QStringLiteral("content-security-policy-report-only"),
        QStringLiteral("x-frame-options"),
        QStringLiteral("strict-transport-security"),
        QStringLiteral("x-content-type-options"),
        QStringLiteral("set-cookie"),
        QStringLiteral("access-control-allow-origin"),
        QStringLiteral("cross-origin-opener-policy"),
        QStringLiteral("cross-origin-embedder-policy"),
        QStringLiteral("referrer-policy"),
    };
    return headers;
}

QString normalizePath(QString p) {
    p.replace(u'\\', u'/');
    while (p.startsWith(u'/')) {
        p.remove(0, 1);
    }
    return p;
}

void collectDnr(const ManifestFacts& manifest, const QList<SourceFile>& files, Signature& sig) {
    for (const RuleResource& rr : manifest.dnrRuleResources) {
        const QString wanted = normalizePath(rr.path);
        for (const SourceFile& f : files) {
            if (f.path != wanted) {
                continue;
            }
            const QJsonDocument doc = QJsonDocument::fromJson(f.content);
            for (const QJsonValue& rv : doc.array()) {
                const QJsonObject rule = rv.toObject();
                sig.dnrRuleCount++;
                const QJsonObject action = rule.value(QStringLiteral("action")).toObject();
                if (action.value(QStringLiteral("type")).toString() != QStringLiteral("modifyHeaders")) {
                    continue;
                }
                for (const char* key : {"responseHeaders", "requestHeaders"}) {
                    for (const QJsonValue& hv : action.value(QLatin1StringView(key)).toArray()) {
                        const QJsonObject h = hv.toObject();
                        const QString header = h.value(QStringLiteral("header")).toString().toLower();
                        if (securityHeaders().contains(header)) {
                            sig.headerMods.append({rr.id, rule.value(QStringLiteral("id")).toInt(), header,
                                                   h.value(QStringLiteral("operation")).toString()});
                        }
                    }
                }
            }
        }
    }
}

void mergeFacts(Signature& sig, const CodeFacts& facts, QHash<QString, int>& domainIndex,
                QSet<QString>& apis, QSet<QString>& fingerprints, QSet<QString>& headers) {
    for (const DomainRef& d : facts.domains) {
        auto it = domainIndex.find(d.host);
        if (it == domainIndex.end()) {
            sig.domains.append(d);
            domainIndex.insert(d.host, static_cast<int>(sig.domains.size()) - 1);
        } else {
            QList<CodeRef>& refs = sig.domains[it.value()].refs;
            for (const CodeRef& r : d.refs) {
                if (refs.size() < 40) {
                    refs.append(r);
                }
            }
        }
    }
    for (const QString& a : facts.chromeApis) {
        apis.insert(a);
    }
    sig.sinks += facts.sinks;
    sig.timers += facts.timers;
    sig.listeners += facts.listeners;
    for (const QString& f : facts.fingerprinting) {
        fingerprints.insert(f);
    }
    if (!facts.fingerprinting.isEmpty()) {
        sig.fingerprintingFiles.append(facts.file);
    }
    for (const QString& h : facts.securityHeaderLiterals) {
        headers.insert(h);
    }
    if (!facts.securityHeaderLiterals.isEmpty()) {
        sig.securityHeaderFiles.append(facts.file);
    }
    sig.dynamicUrls = sig.dynamicUrls || facts.dynamicUrls;
    sig.obfuscation.longBase64Literals += facts.obfuscation.longBase64Literals;
    sig.obfuscation.fromCharCodeCalls += facts.obfuscation.fromCharCodeCalls;
    sig.obfuscation.atobCalls += facts.obfuscation.atobCalls;
    sig.obfuscation.hexEscapedStrings += facts.obfuscation.hexEscapedStrings;
    sig.obfuscation.obfuscatorIdentifiers += facts.obfuscation.obfuscatorIdentifiers;
}

}  // namespace

Signature buildSignature(const ManifestFacts& manifest, const QList<SourceFile>& files,
                         const QString& expectedId) {
    Signature sig;
    sig.version = manifest.version;
    sig.manifest = manifest;
    if (!expectedId.isEmpty() && !manifest.key.isEmpty()) {
        sig.keyMatchesId = extensionIdFromManifestKey(manifest.key) == expectedId;
    }
    for (const ContentScript& cs : manifest.contentScripts) {
        for (const QString& js : cs.js) {
            sig.contentScriptFiles.append(normalizePath(js));
        }
    }
    sig.contentScriptFiles.removeDuplicates();
    collectDnr(manifest, files, sig);

    // Per-file analysis is independent and CPU-bound: run it in parallel, then merge in file
    // order so the result is deterministic.
    struct FileResult {
        FileSummary summary;
        QList<CodeFacts> facts;
        QStringList remoteScripts;
    };
    const auto analyzeOne = [](const SourceFile& f) {
        FileResult r;
        r.summary.path = f.path;
        r.summary.bytes = f.content.size();
        if (isJavaScriptPath(f.path)) {
            // Parse once; analyze the original bytes but report prettified line numbers.
            const JsTree parsed(f.content);
            LineMap map;
            const QString pretty = prettifyJavaScript(parsed, &map);
            CodeFacts facts = analyzeJavaScript(f.path, parsed, &map);
            facts.lineCount = static_cast<int>(pretty.count(u'\n'));
            r.summary.analyzed = true;
            r.summary.lines = facts.lineCount;
            r.summary.parseError = facts.parseError;
            r.facts.append(facts);
        } else if (f.path.endsWith(QStringLiteral(".html"), Qt::CaseInsensitive) ||
                   f.path.endsWith(QStringLiteral(".htm"), Qt::CaseInsensitive)) {
            const HtmlFacts html = analyzeHtml(f.content);
            for (const QString& src : html.scriptSources) {
                if (!hostOfUrl(src).isEmpty()) {
                    r.remoteScripts.append(src);
                }
            }
            int n = 0;
            for (const QByteArray& script : html.inlineScripts) {
                const JsTree parsed(script);
                LineMap map;
                prettifyJavaScript(parsed, &map);
                r.facts.append(analyzeJavaScript(QStringLiteral("%1#inline%2").arg(f.path).arg(++n), parsed, &map));
            }
            r.summary.analyzed = true;
        }
        return r;
    };
    const QList<FileResult> results = QtConcurrent::blockingMapped(files, analyzeOne);

    QHash<QString, int> domainIndex;
    QSet<QString> apis;
    QSet<QString> fingerprints;
    QSet<QString> headers;
    for (const FileResult& r : results) {
        sig.totalBytes += r.summary.bytes;
        sig.files.append(r.summary);
        sig.remoteScriptSources += r.remoteScripts;
        for (const CodeFacts& facts : r.facts) {
            mergeFacts(sig, facts, domainIndex, apis, fingerprints, headers);
        }
    }
    sig.chromeApis = QStringList(apis.begin(), apis.end());
    sig.chromeApis.sort();
    sig.fingerprinting = QStringList(fingerprints.begin(), fingerprints.end());
    sig.fingerprinting.sort();
    sig.securityHeaderLiterals = QStringList(headers.begin(), headers.end());
    sig.securityHeaderLiterals.sort();
    sig.fingerprintingFiles.removeDuplicates();
    sig.securityHeaderFiles.removeDuplicates();
    sig.remoteScriptSources.removeDuplicates();
    std::sort(sig.domains.begin(), sig.domains.end(),
              [](const DomainRef& a, const DomainRef& b) { return a.host < b.host; });
    return sig;
}

namespace {

QJsonObject refToJson(const CodeRef& r) {
    QJsonObject o;
    o.insert(QStringLiteral("file"), r.file);
    o.insert(QStringLiteral("line"), r.line);
    return o;
}

CodeRef refFromJson(const QJsonObject& o) {
    return {o.value(QStringLiteral("file")).toString(), o.value(QStringLiteral("line")).toInt()};
}

}  // namespace

QJsonObject Signature::toJson() const {
    QJsonObject o;
    o.insert(QStringLiteral("schema"), schema);
    o.insert(QStringLiteral("version"), version);
    o.insert(QStringLiteral("key_matches_id"), keyMatchesId);
    QJsonObject m = manifest.toJson();
    m.insert(QStringLiteral("key"), manifest.key);
    m.insert(QStringLiteral("raw"), manifest.raw);
    o.insert(QStringLiteral("manifest"), m);

    QJsonArray mods;
    for (const DnrHeaderMod& h : headerMods) {
        QJsonObject ho;
        ho.insert(QStringLiteral("ruleset"), h.ruleset);
        ho.insert(QStringLiteral("rule_id"), h.ruleId);
        ho.insert(QStringLiteral("header"), h.header);
        ho.insert(QStringLiteral("operation"), h.operation);
        mods.append(ho);
    }
    o.insert(QStringLiteral("dnr_header_mods"), mods);
    o.insert(QStringLiteral("dnr_rule_count"), dnrRuleCount);

    QJsonArray fs;
    for (const FileSummary& f : files) {
        QJsonObject fo;
        fo.insert(QStringLiteral("path"), f.path);
        fo.insert(QStringLiteral("bytes"), f.bytes);
        fo.insert(QStringLiteral("analyzed"), f.analyzed);
        fo.insert(QStringLiteral("lines"), f.lines);
        fo.insert(QStringLiteral("parse_error"), f.parseError);
        fs.append(fo);
    }
    o.insert(QStringLiteral("files"), fs);
    o.insert(QStringLiteral("total_bytes"), totalBytes);
    o.insert(QStringLiteral("content_script_files"), fromStringList(contentScriptFiles));
    o.insert(QStringLiteral("remote_script_sources"), fromStringList(remoteScriptSources));

    QJsonArray ds;
    for (const DomainRef& d : domains) {
        QJsonObject dobj;
        dobj.insert(QStringLiteral("host"), d.host);
        QJsonArray refs;
        for (const CodeRef& r : d.refs) {
            refs.append(refToJson(r));
        }
        dobj.insert(QStringLiteral("refs"), refs);
        ds.append(dobj);
    }
    o.insert(QStringLiteral("domains"), ds);
    o.insert(QStringLiteral("chrome_apis"), fromStringList(chromeApis));

    QJsonArray ss;
    for (const Sink& s : sinks) {
        QJsonObject so;
        so.insert(QStringLiteral("kind"), s.kind);
        so.insert(QStringLiteral("file"), s.file);
        so.insert(QStringLiteral("line"), s.line);
        so.insert(QStringLiteral("evidence"), s.evidence);
        ss.append(so);
    }
    o.insert(QStringLiteral("sinks"), ss);

    QJsonArray ts;
    for (const TimerRef& t : timers) {
        QJsonObject to;
        to.insert(QStringLiteral("kind"), t.kind);
        to.insert(QStringLiteral("ms"), t.ms);
        to.insert(QStringLiteral("string_body"), t.stringBody);
        to.insert(QStringLiteral("file"), t.file);
        to.insert(QStringLiteral("line"), t.line);
        ts.append(to);
    }
    o.insert(QStringLiteral("timers"), ts);

    QJsonArray ls;
    for (const ListenerRef& l : listeners) {
        QJsonObject lo;
        lo.insert(QStringLiteral("event"), l.event);
        lo.insert(QStringLiteral("file"), l.file);
        lo.insert(QStringLiteral("line"), l.line);
        ls.append(lo);
    }
    o.insert(QStringLiteral("listeners"), ls);
    o.insert(QStringLiteral("fingerprinting"), fromStringList(fingerprinting));
    o.insert(QStringLiteral("fingerprinting_files"), fromStringList(fingerprintingFiles));
    o.insert(QStringLiteral("security_header_literals"), fromStringList(securityHeaderLiterals));
    o.insert(QStringLiteral("security_header_files"), fromStringList(securityHeaderFiles));
    o.insert(QStringLiteral("dynamic_urls"), dynamicUrls);
    QJsonObject ob;
    ob.insert(QStringLiteral("long_base64_literals"), obfuscation.longBase64Literals);
    ob.insert(QStringLiteral("from_char_code_calls"), obfuscation.fromCharCodeCalls);
    ob.insert(QStringLiteral("atob_calls"), obfuscation.atobCalls);
    ob.insert(QStringLiteral("hex_escaped_strings"), obfuscation.hexEscapedStrings);
    ob.insert(QStringLiteral("obfuscator_identifiers"), obfuscation.obfuscatorIdentifiers);
    o.insert(QStringLiteral("obfuscation"), ob);
    return o;
}

Signature Signature::fromJson(const QJsonObject& o) {
    Signature s;
    if (o.isEmpty()) {
        return s;
    }
    s.schema = o.value(QStringLiteral("schema")).toInt(1);
    s.version = o.value(QStringLiteral("version")).toString();
    s.keyMatchesId = o.value(QStringLiteral("key_matches_id")).toBool(true);
    const QJsonObject m = o.value(QStringLiteral("manifest")).toObject();
    const QJsonObject raw = m.value(QStringLiteral("raw")).toObject();
    s.manifest = parseManifest(raw, [](const QString& str) { return str; });
    // Names in raw manifests may be __MSG__ placeholders; prefer the resolved ones we stored.
    s.manifest.name = m.value(QStringLiteral("name")).toString(s.manifest.name);
    s.manifest.description = m.value(QStringLiteral("description")).toString(s.manifest.description);
    for (const QJsonValue& v : o.value(QStringLiteral("dnr_header_mods")).toArray()) {
        const QJsonObject h = v.toObject();
        s.headerMods.append({h.value(QStringLiteral("ruleset")).toString(),
                             h.value(QStringLiteral("rule_id")).toInt(),
                             h.value(QStringLiteral("header")).toString(),
                             h.value(QStringLiteral("operation")).toString()});
    }
    s.dnrRuleCount = o.value(QStringLiteral("dnr_rule_count")).toInt();
    for (const QJsonValue& v : o.value(QStringLiteral("files")).toArray()) {
        const QJsonObject f = v.toObject();
        s.files.append({f.value(QStringLiteral("path")).toString(),
                        static_cast<qint64>(f.value(QStringLiteral("bytes")).toDouble()),
                        f.value(QStringLiteral("analyzed")).toBool(),
                        f.value(QStringLiteral("lines")).toInt(),
                        f.value(QStringLiteral("parse_error")).toBool()});
    }
    s.totalBytes = static_cast<qint64>(o.value(QStringLiteral("total_bytes")).toDouble());
    s.contentScriptFiles = toStringList(o.value(QStringLiteral("content_script_files")));
    s.remoteScriptSources = toStringList(o.value(QStringLiteral("remote_script_sources")));
    for (const QJsonValue& v : o.value(QStringLiteral("domains")).toArray()) {
        const QJsonObject d = v.toObject();
        DomainRef ref;
        ref.host = d.value(QStringLiteral("host")).toString();
        for (const QJsonValue& r : d.value(QStringLiteral("refs")).toArray()) {
            ref.refs.append(refFromJson(r.toObject()));
        }
        s.domains.append(ref);
    }
    s.chromeApis = toStringList(o.value(QStringLiteral("chrome_apis")));
    for (const QJsonValue& v : o.value(QStringLiteral("sinks")).toArray()) {
        const QJsonObject k = v.toObject();
        s.sinks.append({k.value(QStringLiteral("kind")).toString(), k.value(QStringLiteral("file")).toString(),
                        k.value(QStringLiteral("line")).toInt(), k.value(QStringLiteral("evidence")).toString()});
    }
    for (const QJsonValue& v : o.value(QStringLiteral("timers")).toArray()) {
        const QJsonObject t = v.toObject();
        TimerRef tr;
        tr.kind = t.value(QStringLiteral("kind")).toString();
        tr.ms = static_cast<qint64>(t.value(QStringLiteral("ms")).toDouble());
        tr.stringBody = t.value(QStringLiteral("string_body")).toBool();
        tr.file = t.value(QStringLiteral("file")).toString();
        tr.line = t.value(QStringLiteral("line")).toInt();
        s.timers.append(tr);
    }
    for (const QJsonValue& v : o.value(QStringLiteral("listeners")).toArray()) {
        const QJsonObject l = v.toObject();
        s.listeners.append({l.value(QStringLiteral("event")).toString(), l.value(QStringLiteral("file")).toString(),
                            l.value(QStringLiteral("line")).toInt()});
    }
    s.fingerprinting = toStringList(o.value(QStringLiteral("fingerprinting")));
    s.fingerprintingFiles = toStringList(o.value(QStringLiteral("fingerprinting_files")));
    s.securityHeaderLiterals = toStringList(o.value(QStringLiteral("security_header_literals")));
    s.securityHeaderFiles = toStringList(o.value(QStringLiteral("security_header_files")));
    s.dynamicUrls = o.value(QStringLiteral("dynamic_urls")).toBool();
    const QJsonObject ob = o.value(QStringLiteral("obfuscation")).toObject();
    s.obfuscation.longBase64Literals = ob.value(QStringLiteral("long_base64_literals")).toInt();
    s.obfuscation.fromCharCodeCalls = ob.value(QStringLiteral("from_char_code_calls")).toInt();
    s.obfuscation.atobCalls = ob.value(QStringLiteral("atob_calls")).toInt();
    s.obfuscation.hexEscapedStrings = ob.value(QStringLiteral("hex_escaped_strings")).toInt();
    s.obfuscation.obfuscatorIdentifiers = ob.value(QStringLiteral("obfuscator_identifiers")).toInt();
    return s;
}

}  // namespace extwatch
