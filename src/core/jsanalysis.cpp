#include "core/jsanalysis.h"

#include <tree_sitter/api.h>

#include <QRegularExpression>
#include <QSet>
#include <cstring>
#include <string>
#include <string_view>

namespace extwatch {

QString hostOfUrl(const QString& url) {
    static const QRegularExpression re(
        QStringLiteral("^(?:https?|wss?)://([A-Za-z0-9.-]+)(?::\\d+)?(?:[/?#]|$)"),
        QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch m = re.match(url.trimmed());
    if (!m.hasMatch()) {
        return {};
    }
    const QString host = m.captured(1).toLower();
    if (host == QStringLiteral("localhost") || host.startsWith(QStringLiteral("127.")) ||
        host == QStringLiteral("0.0.0.0") || !host.contains(u'.')) {
        return {};
    }
    return host;
}

namespace {

using sv = std::string_view;

bool startsWith(sv s, sv prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

bool endsWith(sv s, sv suffix) {
    return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

sv lastSegment(sv callee) {
    const size_t dot = callee.rfind('.');
    return dot == sv::npos ? callee : callee.substr(dot + 1);
}

bool isIdentifierChars(sv s) {
    for (const char c : s) {
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '$')) {
            return false;
        }
    }
    return !s.empty();
}

struct Walker {
    const QByteArray& src;
    CodeFacts& facts;
    const LineMap* map;
    QSet<QString> apiSet;
    QSet<QString> fingerprintSet;
    QSet<QString> headerSet;
    QHash<QString, int> domainIndex;
    QHash<QString, qint64> constants;  // const FIVE_MINUTES = 5 * 60 * 1000
    bool depthExceeded = false;

    sv view(TSNode n) const {
        const uint32_t a = ts_node_start_byte(n);
        const uint32_t b = ts_node_end_byte(n);
        return sv(src.constData() + a, b - a);
    }
    QString text(TSNode n) const {
        const sv v = view(n);
        return QString::fromUtf8(v.data(), static_cast<qsizetype>(v.size()));
    }
    QString excerpt(TSNode n) const {
        QString t = text(n).simplified();
        if (t.size() > 120) {
            t = t.left(117) + QStringLiteral("...");
        }
        return t;
    }
    int line(TSNode n) const {
        if (map) {
            return map->lineFor(ts_node_start_byte(n));
        }
        return static_cast<int>(ts_node_start_point(n).row) + 1;
    }
    static const char* type(TSNode n) { return ts_node_type(n); }
    static bool typeIs(TSNode n, const char* t) { return std::strcmp(ts_node_type(n), t) == 0; }

    static TSNode field(TSNode n, const char* name) {
        return ts_node_child_by_field_name(n, name, static_cast<uint32_t>(std::strlen(name)));
    }

    void addDomain(const QString& host, TSNode at) {
        if (host.isEmpty()) {
            return;
        }
        auto it = domainIndex.find(host);
        if (it == domainIndex.end()) {
            facts.domains.append({host, {}});
            it = domainIndex.insert(host, static_cast<int>(facts.domains.size()) - 1);
        }
        QList<CodeRef>& refs = facts.domains[it.value()].refs;
        if (refs.size() < 20) {
            refs.append({facts.file, line(at)});
        }
    }

    void addSink(const char* kind, TSNode at) {
        facts.sinks.append({QString::fromLatin1(kind), facts.file, line(at), excerpt(at)});
    }

    bool isStringLike(TSNode n) const {
        return typeIs(n, "string") || typeIs(n, "template_string");
    }

    // Literal content without the quotes.
    sv literalView(TSNode n) const {
        const sv v = view(n);
        return v.size() >= 2 ? v.substr(1, v.size() - 2) : sv();
    }

    void scanStringLiteral(TSNode n, bool isTemplate) {
        const sv value = literalView(n);
        if (value.empty()) {
            return;
        }
        if (value.find("://") != sv::npos) {
            static const QRegularExpression urlRe(
                QStringLiteral("(?:https?|wss?)://[A-Za-z0-9.-]+(?::\\d+)?(?:[/?#][^\\s'\"`<>]*)?"),
                QRegularExpression::CaseInsensitiveOption);
            const QString qvalue = QString::fromUtf8(value.data(), static_cast<qsizetype>(value.size()));
            QRegularExpressionMatchIterator it = urlRe.globalMatch(qvalue);
            while (it.hasNext()) {
                addDomain(hostOfUrl(it.next().captured(0)), n);
            }
            if (isTemplate && value.find("://${") != sv::npos) {
                facts.dynamicUrls = true;
            }
        }
        if (value.size() <= 40 && value.find('-') != sv::npos) {
            static const char* const headers[] = {
                "content-security-policy", "x-frame-options", "content-security-policy-report-only",
                "strict-transport-security", "set-cookie", "x-content-type-options",
                "access-control-allow-origin",
            };
            QByteArray lower(value.data(), static_cast<qsizetype>(value.size()));
            lower = lower.toLower();
            for (const char* h : headers) {
                if (lower == h) {
                    headerSet.insert(QString::fromLatin1(h));
                }
            }
        }
        if (value.size() >= 100) {
            bool base64 = true;
            for (const char c : value) {
                if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '+' || c == '/' || c == '=' ||
                      c == '_' || c == '-')) {
                    base64 = false;
                    break;
                }
            }
            if (base64) {
                facts.obfuscation.longBase64Literals++;
            }
        }
        if (value.find("\\x") != sv::npos || value.find("\\u") != sv::npos) {
            int escapes = 0;
            for (size_t pos = value.find('\\'); pos != sv::npos && pos + 1 < value.size() && escapes < 4;
                 pos = value.find('\\', pos + 2)) {
                if (value[pos + 1] == 'x' || value[pos + 1] == 'u') {
                    ++escapes;
                }
            }
            if (escapes >= 4) {
                facts.obfuscation.hexEscapedStrings++;
            }
        }
    }

    void scanMemberExpression(TSNode n) {
        const sv full = view(n);
        if (full.size() > 80 || full.find('\n') != sv::npos) {
            return;
        }
        sv rest;
        if (startsWith(full, "chrome.")) {
            rest = full.substr(7);
        } else if (startsWith(full, "browser.")) {
            rest = full.substr(8);
        }
        if (!rest.empty()) {
            // Up to three identifier segments; storage areas (local/sync/session) count as one.
            QString api = QStringLiteral("chrome");
            int segments = 0;
            sv ns;
            while (!rest.empty() && segments < 3) {
                const size_t dot = rest.find('.');
                const sv seg = dot == sv::npos ? rest : rest.substr(0, dot);
                if (!isIdentifierChars(seg)) {
                    return;
                }
                if (segments == 2 && (ns == "local" || ns == "sync" || ns == "session")) {
                    break;
                }
                api += u'.' + QString::fromUtf8(seg.data(), static_cast<qsizetype>(seg.size()));
                if (segments == 1) {
                    ns = seg;
                }
                ++segments;
                if (dot == sv::npos) {
                    break;
                }
                rest = rest.substr(dot + 1);
            }
            if (segments > 0) {
                apiSet.insert(api);
            }
            return;
        }
        if (startsWith(full, "navigator.") || startsWith(full, "screen.") || endsWith(full, "resolvedOptions().timeZone")) {
            static const char* const fingerprints[] = {
                "navigator.language",  "navigator.languages",  "navigator.userAgent",
                "navigator.platform",  "navigator.hardwareConcurrency", "navigator.deviceMemory",
                "screen.width",        "screen.height",        "navigator.plugins",
                "navigator.userAgentData",
            };
            for (const char* f : fingerprints) {
                if (full == f) {
                    fingerprintSet.insert(QString::fromLatin1(f));
                    return;
                }
            }
            if (endsWith(full, "resolvedOptions().timeZone")) {
                fingerprintSet.insert(QStringLiteral("Intl.DateTimeFormat().resolvedOptions().timeZone"));
            }
        }
    }

    sv calleeName(TSNode call) const {
        const TSNode fn = field(call, "function");
        if (ts_node_is_null(fn)) {
            return {};
        }
        const sv t = view(fn);
        return t.size() <= 100 && t.find('\n') == sv::npos ? t : sv();
    }

    qint64 numericPeriod(TSNode arg) const {
        const sv expr = view(arg);
        if (typeIs(arg, "number")) {
            QByteArray digits(expr.data(), static_cast<qsizetype>(expr.size()));
            digits.replace("_", "");
            bool ok = false;
            const qint64 v = digits.toLongLong(&ok);
            return ok ? v : 0;
        }
        // 5 * 60 * 1000 style products
        qint64 product = 1;
        bool any = false;
        qint64 current = 0;
        bool inNumber = false;
        for (const char c : expr) {
            if (std::isdigit(static_cast<unsigned char>(c))) {
                current = current * 10 + (c - '0');
                inNumber = true;
            } else if (c == '*' || c == ' ' || c == '(' || c == ')' || c == '\n' || c == '_') {
                if (inNumber) {
                    product *= current;
                    any = true;
                    current = 0;
                    inNumber = false;
                }
            } else {
                return 0;
            }
        }
        if (inNumber) {
            product *= current;
            any = true;
        }
        return any ? product : 0;
    }

    // Normalizes a callee for comparison: strips window./self./globalThis., maps browser.* to
    // chrome.*, and unwraps the (0, eval) and globalThis["eval"] spellings.
    static std::string normalizeCallee(sv callee) {
        std::string c(callee);
        for (const char* prefix : {"window.", "self.", "globalThis."}) {
            const size_t len = std::strlen(prefix);
            if (c.compare(0, len, prefix) == 0) {
                c.erase(0, len);
                break;
            }
        }
        if (c.compare(0, 8, "browser.") == 0) {
            c.replace(0, 8, "chrome.");
        }
        if (!c.empty() && c.front() == '(' && c.back() == ')') {
            // (0, eval) or (0, window.eval)
            const size_t comma = c.rfind(',');
            std::string inner = comma == std::string::npos ? c.substr(1, c.size() - 2) : c.substr(comma + 1, c.size() - comma - 2);
            while (!inner.empty() && inner.front() == ' ') inner.erase(0, 1);
            while (!inner.empty() && inner.back() == ' ') inner.pop_back();
            c = normalizeCallee(inner);
        }
        for (const char* form : {"[\"eval\"]", "['eval']"}) {
            if (c.size() >= std::strlen(form) && c.compare(c.size() - std::strlen(form), std::strlen(form), form) == 0) {
                c = "eval";
            }
        }
        return c;
    }

    void scanCall(TSNode call) {
        const sv rawCallee = calleeName(call);
        if (rawCallee.empty()) {
            return;
        }
        const std::string normalized = normalizeCallee(rawCallee);
        const sv callee(normalized);
        const TSNode args = field(call, "arguments");
        const uint32_t argCount = ts_node_is_null(args) ? 0 : ts_node_named_child_count(args);
        auto arg = [&](uint32_t i) { return ts_node_named_child(args, i); };
        const sv last = lastSegment(callee);

        if (callee == "eval") {
            addSink("eval", call);
        } else if (callee == "Function") {
            addSink("new_function", call);  // Function(payload)() without new
        } else if (callee == "setTimeout" || callee == "setInterval") {
            TimerRef t;
            t.kind = QString::fromUtf8(callee.data(), static_cast<qsizetype>(callee.size()));
            t.file = facts.file;
            t.line = line(call);
            if (argCount >= 1 && isStringLike(arg(0))) {
                t.stringBody = true;
                addSink("timer_string", call);
            }
            if (argCount >= 2) {
                t.ms = numericPeriod(arg(1));
                if (t.ms == 0 && typeIs(arg(1), "identifier")) {
                    t.argName = text(arg(1));
                }
            }
            facts.timers.append(t);
        } else if (callee == "chrome.alarms.create") {
            // chrome.alarms.create(name?, { periodInMinutes: 5 }) is the service-worker-friendly poll timer.
            TimerRef t;
            t.kind = QStringLiteral("alarm");
            t.file = facts.file;
            t.line = line(call);
            for (uint32_t i = 0; i < argCount; ++i) {
                const TSNode a = arg(i);
                if (!typeIs(a, "object")) {
                    continue;
                }
                const uint32_t pairs = ts_node_named_child_count(a);
                for (uint32_t k = 0; k < pairs; ++k) {
                    const TSNode pair = ts_node_named_child(a, k);
                    if (!typeIs(pair, "pair")) {
                        continue;
                    }
                    const TSNode key = field(pair, "key");
                    const TSNode value = field(pair, "value");
                    if (ts_node_is_null(key) || ts_node_is_null(value)) {
                        continue;
                    }
                    const sv keyText = view(key);
                    if (keyText == "periodInMinutes" || keyText == "\"periodInMinutes\"" || keyText == "'periodInMinutes'") {
                        const sv v = view(value);
                        const double minutes = QByteArray(v.data(), static_cast<qsizetype>(v.size())).toDouble();
                        if (minutes > 0) {
                            t.ms = static_cast<qint64>(minutes * 60000.0);
                        }
                    }
                }
            }
            facts.timers.append(t);
        } else if (callee == "chrome.scripting.registerContentScripts" ||
                   callee == "chrome.scripting.updateContentScripts" || callee == "chrome.userScripts.register") {
            addSink("register_content_scripts", call);
        } else if (startsWith(callee, "WebAssembly.") &&
                   (last == "instantiate" || last == "instantiateStreaming" || last == "compile" || last == "compileStreaming")) {
            addSink("wasm_instantiate", call);
        } else if (last == "importScripts") {
            bool remote = false;
            bool dynamic = false;
            for (uint32_t i = 0; i < argCount; ++i) {
                if (isStringLike(arg(i))) {
                    const sv v = literalView(arg(i));
                    if (v.find("://") != sv::npos &&
                        !hostOfUrl(QString::fromUtf8(v.data(), static_cast<qsizetype>(v.size()))).isEmpty()) {
                        remote = true;
                    }
                } else {
                    dynamic = true;
                }
            }
            addSink(remote ? "import_scripts_remote" : dynamic ? "import_scripts_dynamic" : "import_scripts_local", call);
        } else if (last == "setAttribute" && argCount >= 2 && isStringLike(arg(0))) {
            QByteArray attr(literalView(arg(0)).data(), static_cast<qsizetype>(literalView(arg(0)).size()));
            attr = attr.toLower();
            if (attr.startsWith("on")) {
                // A constant handler such as setAttribute("oninput", "return;") is a framework
                // workaround, not a loader; the loader pattern passes a variable or a template.
                const bool constant = typeIs(arg(1), "string");
                if (!constant) {
                    addSink("attribute_exec", call);
                }
            } else if ((attr == "src" || attr == "href") && !isStringLike(arg(1))) {
                addSink("src_assignment", call);
            }
        } else if (last == "createElement" && argCount >= 1 && isStringLike(arg(0))) {
            QByteArray tag(literalView(arg(0)).data(), static_cast<qsizetype>(literalView(arg(0)).size()));
            tag = tag.toLower();
            if (tag == "script") {
                addSink("script_element", call);
            } else if (tag == "iframe") {
                addSink("iframe_element", call);
            }
        } else if (callee == "fetch" || callee == "window.fetch" || callee == "self.fetch" || callee == "globalThis.fetch") {
            addSink("fetch", call);
        } else if (last == "sendBeacon") {
            addSink("beacon", call);
        } else if (last == "open" && (callee.find("xhr") != sv::npos || callee.find("Xhr") != sv::npos ||
                                      callee.find("XHR") != sv::npos || callee.find("Request") != sv::npos)) {
            addSink("xhr", call);
        } else if (callee == "chrome.runtime.sendNativeMessage" || callee == "chrome.runtime.connectNative") {
            addSink("native_messaging", call);
        } else if (startsWith(callee, "chrome.storage.") && last == "get") {
            addSink("storage_get", call);
        } else if (callee == "chrome.declarativeNetRequest.updateDynamicRules" ||
                   callee == "chrome.declarativeNetRequest.updateSessionRules") {
            addSink("dnr_dynamic_rules", call);
        } else if (callee == "chrome.webRequest.onHeadersReceived.addListener" ||
                   callee == "chrome.webRequest.onBeforeSendHeaders.addListener") {
            addSink("webrequest_headers", call);
        } else if (callee == "chrome.scripting.executeScript" || callee == "chrome.tabs.executeScript") {
            addSink("execute_script", call);
        } else if (last == "addEventListener" && argCount >= 1 && isStringLike(arg(0))) {
            QByteArray ev(literalView(arg(0)).data(), static_cast<qsizetype>(literalView(arg(0)).size()));
            ev = ev.toLower();
            static const char* const interesting[] = {"keydown", "keypress", "keyup", "input", "paste",
                                                      "submit", "change", "copy", "beforeunload"};
            for (const char* e : interesting) {
                if (ev == e) {
                    facts.listeners.append({QString::fromLatin1(e), facts.file, line(call)});
                    break;
                }
            }
        } else if (callee == "String.fromCharCode") {
            facts.obfuscation.fromCharCodeCalls++;
        } else if (callee == "atob" || callee == "window.atob" || callee == "self.atob") {
            facts.obfuscation.atobCalls++;
        }
    }

    void scanNew(TSNode n) {
        const TSNode ctor = field(n, "constructor");
        if (ts_node_is_null(ctor)) {
            return;
        }
        const sv name = view(ctor);
        if (name == "Function") {
            // new Function("") and new Function("return this") are the usual globalThis polyfill.
            const TSNode args = field(n, "arguments");
            if (!ts_node_is_null(args) && ts_node_named_child_count(args) == 1) {
                const TSNode a = ts_node_named_child(args, 0);
                if (isStringLike(a)) {
                    const sv body = literalView(a);
                    if (body.empty() || body == "return this") {
                        return;
                    }
                }
            }
            addSink("new_function", n);
        } else if (name == "WebSocket") {
            addSink("websocket", n);
        } else if (name == "XMLHttpRequest") {
            addSink("xhr", n);
        } else if (name == "EventSource") {
            addSink("event_source", n);
        }
    }

    void scanAssignment(TSNode n) {
        const TSNode left = field(n, "left");
        const TSNode right = field(n, "right");
        if (ts_node_is_null(left) || ts_node_is_null(right) || !typeIs(left, "member_expression")) {
            return;
        }
        const TSNode prop = field(left, "property");
        if (ts_node_is_null(prop)) {
            return;
        }
        const sv property = view(prop);
        if (property == "innerHTML" || property == "outerHTML") {
            if (!isStringLike(right)) {
                addSink("inner_html", n);
            }
        } else if (property.size() > 2 && property[0] == 'o' && property[1] == 'n' && isStringLike(right)) {
            addSink("attribute_exec", n);
        } else if (property == "src") {
            if (!isStringLike(right)) {
                addSink("src_assignment", n);
            } else if (literalView(right).find("://") != sv::npos) {
                addSink("src_remote_literal", n);
            }
        } else if (property == "href" && endsWith(view(left), "location.href")) {
            const sv v = literalView(right);
            if (isStringLike(right) && v.size() >= 11 &&
                QByteArray(v.data(), 11).toLower() == "javascript:") {
                addSink("javascript_url", n);
            }
        }
    }

    void visit(TSNode n, int depth) {
        if (ts_node_is_named(n)) {
            switch (kindForSymbol(ts_node_symbol(n))) {
                case NodeKind::String:
                    scanStringLiteral(n, false);
                    return;
                case NodeKind::TemplateString:
                    scanStringLiteral(n, true);
                    break;
                case NodeKind::MemberExpression:
                    scanMemberExpression(n);
                    break;
                case NodeKind::CallExpression:
                    scanCall(n);
                    break;
                case NodeKind::NewExpression:
                    scanNew(n);
                    break;
                case NodeKind::AssignmentExpression:
                    scanAssignment(n);
                    break;
                case NodeKind::Other:
                    if (typeIs(n, "variable_declarator")) {
                        const TSNode name = field(n, "name");
                        const TSNode value = field(n, "value");
                        if (!ts_node_is_null(name) && !ts_node_is_null(value) && typeIs(name, "identifier")) {
                            const qint64 ms = numericPeriod(value);
                            if (ms > 0) {
                                const QString id = text(name);
                                if (!constants.contains(id)) {
                                    constants.insert(id, ms);
                                }
                            }
                        }
                    }
                    break;
                case NodeKind::Identifier:
                case NodeKind::PropertyIdentifier: {
                    const sv id = view(n);
                    if (id.size() >= 4 && id[0] == '_' && id[1] == '0' && id[2] == 'x') {
                        facts.obfuscation.obfuscatorIdentifiers++;
                    }
                    return;
                }
                default:
                    if (ts_node_is_error(n)) {
                        facts.parseError = true;
                    }
                    break;
            }
        }
        if (depth > 400) {
            depthExceeded = true;
            return;
        }
        if (ts_node_child_count(n) == 0) {
            return;
        }
        TSTreeCursor cursor = ts_tree_cursor_new(n);
        if (ts_tree_cursor_goto_first_child(&cursor)) {
            do {
                visit(ts_tree_cursor_current_node(&cursor), depth + 1);
            } while (ts_tree_cursor_goto_next_sibling(&cursor));
        }
        ts_tree_cursor_delete(&cursor);
    }
};

}  // namespace

CodeFacts analyzeJavaScript(const QString& file, const JsTree& parsed, const LineMap* map) {
    CodeFacts facts;
    facts.file = file;
    const QByteArray& src = parsed.source();
    facts.lineCount = static_cast<int>(src.count('\n')) + (src.isEmpty() ? 0 : 1);
    if (!parsed.ok()) {
        facts.parseError = true;
        return facts;
    }
    Walker w{src, facts, map, {}, {}, {}, {}};
    const TSNode root = ts_tree_root_node(parsed.tree());
    if (ts_node_has_error(root)) {
        facts.parseError = true;
    }
    w.visit(root, 0);
    for (TimerRef& t : facts.timers) {
        if (t.ms == 0 && !t.argName.isEmpty()) {
            t.ms = w.constants.value(t.argName, 0);
        }
    }
    if (w.depthExceeded) {
        facts.warnings.append(QStringLiteral("nesting deeper than 400 levels was not analyzed"));
    }
    if (facts.parseError) {
        facts.warnings.append(QStringLiteral("parse errors; some code may be skipped"));
    }
    // Bidirectional overrides and isolates, zero-width characters and stray BOMs can make code
    // read differently from how it runs (Trojan Source).
    for (qsizetype i = 0; i + 2 < src.size(); ++i) {
        const unsigned char a = static_cast<unsigned char>(src.at(i));
        if (a != 0xE2 && a != 0xEF) {
            continue;
        }
        const unsigned char b = static_cast<unsigned char>(src.at(i + 1));
        const unsigned char c = static_cast<unsigned char>(src.at(i + 2));
        const bool bidi = a == 0xE2 && b == 0x80 && c >= 0xAA && c <= 0xAE;      // U+202A..U+202E
        const bool isolate = a == 0xE2 && b == 0x81 && c >= 0xA6 && c <= 0xA9;   // U+2066..U+2069
        const bool zeroWidth = a == 0xE2 && b == 0x80 && c >= 0x8B && c <= 0x8D; // U+200B..U+200D
        const bool bom = a == 0xEF && b == 0xBB && c == 0xBF && i > 0;           // U+FEFF inside the file
        if (bidi || isolate || zeroWidth || bom) {
            facts.obfuscation.invisibleChars++;
        }
    }
    facts.chromeApis = QStringList(w.apiSet.begin(), w.apiSet.end());
    facts.chromeApis.sort();
    facts.fingerprinting = QStringList(w.fingerprintSet.begin(), w.fingerprintSet.end());
    facts.fingerprinting.sort();
    facts.securityHeaderLiterals = QStringList(w.headerSet.begin(), w.headerSet.end());
    facts.securityHeaderLiterals.sort();
    std::sort(facts.domains.begin(), facts.domains.end(),
              [](const DomainRef& a, const DomainRef& b) { return a.host < b.host; });
    return facts;
}

CodeFacts analyzeJavaScript(const QString& file, const QByteArray& utf8Source) {
    const JsTree parsed(utf8Source);
    return analyzeJavaScript(file, parsed, nullptr);
}

HtmlFacts analyzeHtml(const QByteArray& html) {
    HtmlFacts out;
    const QString text = QString::fromUtf8(html);
    static const QRegularExpression scriptRe(
        QStringLiteral("<script\\b([^>]*)>(.*?)</script>"),
        QRegularExpression::CaseInsensitiveOption | QRegularExpression::DotMatchesEverythingOption);
    static const QRegularExpression srcRe(QStringLiteral("\\bsrc\\s*=\\s*[\"']([^\"']+)[\"']"),
                                          QRegularExpression::CaseInsensitiveOption);
    QRegularExpressionMatchIterator it = scriptRe.globalMatch(text);
    while (it.hasNext()) {
        const QRegularExpressionMatch m = it.next();
        const QRegularExpressionMatch src = srcRe.match(m.captured(1));
        if (src.hasMatch()) {
            out.scriptSources.append(src.captured(1));
        } else if (!m.captured(2).trimmed().isEmpty()) {
            out.inlineScripts.append(m.captured(2).toUtf8());
        }
    }
    return out;
}

}  // namespace extwatch
