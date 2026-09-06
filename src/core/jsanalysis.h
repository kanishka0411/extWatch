#pragma once

#include <QByteArray>
#include <QJsonObject>
#include <QList>
#include <QString>
#include <QStringList>

#include "core/jstree.h"

namespace extwatch {

// A location inside a (prettified) source file. Lines are 1-based.
struct CodeRef {
    QString file;
    int line = 0;
};

struct DomainRef {
    QString host;
    QList<CodeRef> refs;
};

// A call or assignment that can load or execute code, move data, or change headers.
struct Sink {
    QString kind;      // eval, new_function, timer_string, attribute_exec, import_scripts_remote,
                       // import_scripts_dynamic, script_element, src_assignment, inner_html,
                       // javascript_url, fetch, xhr, websocket, beacon, native_messaging,
                       // storage_get, dnr_dynamic_rules, webrequest_headers, execute_script
    QString file;
    int line = 0;
    QString evidence;  // short source excerpt
};

struct TimerRef {
    QString kind;  // setInterval, setTimeout or alarm (chrome.alarms.create)
    qint64 ms = 0;  // 0 when the period could not be resolved
    bool stringBody = false;
    QString file;
    int line = 0;
    QString argName;  // identifier used as the period, resolved against file-level constants
};

struct ListenerRef {
    QString event;
    QString file;
    int line = 0;
};

struct ObfuscationStats {
    int longBase64Literals = 0;
    int fromCharCodeCalls = 0;
    int atobCalls = 0;
    int hexEscapedStrings = 0;
    int obfuscatorIdentifiers = 0;  // _0x1a2b style names
    int invisibleChars = 0;         // bidi overrides, isolates, zero-width and BOM characters
    int total() const {
        return longBase64Literals + fromCharCodeCalls + atobCalls + hexEscapedStrings +
               obfuscatorIdentifiers;
    }
};

// Everything we extract from one JavaScript file.
struct CodeFacts {
    QString file;
    bool parseError = false;
    int lineCount = 0;
    QList<DomainRef> domains;
    QStringList chromeApis;           // chrome.tabs.captureVisibleTab, ...
    QList<Sink> sinks;
    QList<TimerRef> timers;
    QList<ListenerRef> listeners;
    QStringList fingerprinting;       // navigator.language, ... (unique)
    QStringList securityHeaderLiterals;  // content-security-policy, x-frame-options, ...
    bool dynamicUrls = false;         // template URL with a substituted host
    ObfuscationStats obfuscation;
    QStringList warnings;             // reasons the analysis is incomplete (depth limit, parse errors)
};

// Analyzes JavaScript. With a LineMap (from prettifyJavaScript on the same tree) the reported
// lines refer to the prettified text the diff viewer shows; without one they refer to the
// analyzed source itself.
CodeFacts analyzeJavaScript(const QString& file, const JsTree& parsed, const LineMap* map = nullptr);
CodeFacts analyzeJavaScript(const QString& file, const QByteArray& utf8Source);

// Extracts inline <script> bodies and external <script src> targets from an HTML file.
struct HtmlFacts {
    QStringList scriptSources;
    QList<QByteArray> inlineScripts;
};
HtmlFacts analyzeHtml(const QByteArray& html);

// Host of an absolute http(s)/ws(s) URL, lower-cased; empty when not a remote URL.
QString hostOfUrl(const QString& url);

}  // namespace extwatch
