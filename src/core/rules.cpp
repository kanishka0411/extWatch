#include "core/rules.h"

#include <QHash>
#include <QJsonDocument>
#include <QSet>
#include <QUrl>
#include <algorithm>

#include "core/jsanalysis.h"

namespace extwatch {

QString severityId(Severity s) {
    switch (s) {
        case Severity::High: return QStringLiteral("high");
        case Severity::Medium: return QStringLiteral("medium");
        case Severity::Low: return QStringLiteral("low");
        case Severity::Info: return QStringLiteral("info");
    }
    return QStringLiteral("info");
}

Severity severityFromId(const QString& id) {
    if (id == QStringLiteral("high")) return Severity::High;
    if (id == QStringLiteral("medium")) return Severity::Medium;
    if (id == QStringLiteral("low")) return Severity::Low;
    return Severity::Info;
}

QJsonObject Finding::toJson() const {
    QJsonObject o;
    o.insert(QStringLiteral("rule"), rule);
    o.insert(QStringLiteral("severity"), severityId(severity));
    o.insert(QStringLiteral("title"), title);
    o.insert(QStringLiteral("detail"), detail);
    if (!file.isEmpty()) {
        o.insert(QStringLiteral("file"), file);
        o.insert(QStringLiteral("line"), line);
    }
    return o;
}

Finding Finding::fromJson(const QJsonObject& o) {
    Finding f;
    f.rule = o.value(QStringLiteral("rule")).toString();
    f.severity = severityFromId(o.value(QStringLiteral("severity")).toString());
    f.title = o.value(QStringLiteral("title")).toString();
    f.detail = o.value(QStringLiteral("detail")).toString();
    f.file = o.value(QStringLiteral("file")).toString();
    f.line = o.value(QStringLiteral("line")).toInt();
    return f;
}

QJsonArray findingsToJson(const QList<Finding>& findings) {
    QJsonArray a;
    for (const Finding& f : findings) {
        a.append(f.toJson());
    }
    return a;
}

QList<Finding> findingsFromJson(const QJsonArray& array) {
    QList<Finding> out;
    for (const QJsonValue& v : array) {
        out.append(Finding::fromJson(v.toObject()));
    }
    return out;
}

Severity maxSeverity(const QList<Finding>& findings) {
    Severity m = Severity::Info;
    for (const Finding& f : findings) {
        if (f.severity > m) {
            m = f.severity;
        }
    }
    return m;
}

namespace {

#define RULE(id, sev, title, explanation) {QStringLiteral(id), Severity::sev, QStringLiteral(title), QStringLiteral(explanation)}

const QList<RuleInfo> kRules = {
    RULE("host.all_urls", High, "Gains access to every website",
         "A new <all_urls> or *://*/* host pattern lets the extension read and change every page you visit."),
    RULE("network.poller", High, "Polls a server on a timer",
         "A periodic timer and a network call to a new domain in the same file: the extension keeps asking a server what to do."),
    RULE("host.broadened", Medium, "Gains access to more websites",
         "New host patterns were added to host_permissions or content script matches."),
    RULE("content_scripts.broadened", Medium, "Injects code into more pages or frames",
         "Content scripts now match more URLs, run in all frames, or run before the page loads."),
    RULE("permission.sensitive", Medium, "Requests a sensitive browser API",
         "APIs such as cookies, history, webRequest, tabs, scripting, debugger or nativeMessaging expose browsing data or code execution."),
    RULE("permission.added", Low, "Requests a new browser API", "A new API permission that is not in the sensitive set."),
    RULE("remote_code.eval", High, "Executes dynamically built code",
         "eval, new Function or a timer with a string body can run code that is not in the shipped files."),
    RULE("remote_code.attribute_exec", High, "Executes code through an event-handler attribute",
         "Setting an on* attribute to a string runs that string as JavaScript. Used by QuickLens to run server-supplied code on every page."),
    RULE("remote_code.import_scripts", High, "Loads scripts from a remote server",
         "importScripts with a remote URL pulls executable code from outside the package."),
    RULE("remote_code.import_scripts_dynamic", Medium, "Loads scripts from a computed location",
         "importScripts is called with a non-literal argument."),
    RULE("remote_code.html_script", High, "Extension page loads a remote script",
         "A <script src=\"https://...\"> in an extension page executes code from a server."),
    RULE("remote_code.javascript_url", High, "Navigates to a javascript: URL", "javascript: URLs execute their content."),
    RULE("remote_code.storage_to_exec", High, "Runs code that was fetched into storage",
         "The same file reads chrome.storage and executes strings, the pattern of a payload cached from a remote server."),
    RULE("network.domain", Medium, "Talks to a new domain", "A network endpoint that earlier versions did not contact."),
    RULE("network.domain_known", Low, "Talks to a new well-known domain", "The domain is common infrastructure (Google, GitHub, a public CDN, or the extension's own homepage)."),
    RULE("network.dynamic_url", Low, "Builds request URLs at runtime", "The host of a request is computed, so it cannot be read from the code."),
    RULE("headers.strip_security", High, "Removes security headers from web pages",
         "A declarativeNetRequest rule or webRequest listener removes or rewrites Content-Security-Policy, X-Frame-Options or similar headers, disabling the protections of every site."),
    RULE("headers.dynamic_rules", Medium, "Changes network rules at runtime",
         "Dynamic declarativeNetRequest rules or webRequest header listeners can rewrite traffic in ways not visible in the package."),
    RULE("scripting.execute", Medium, "Injects scripts into tabs programmatically", "chrome.scripting.executeScript or tabs.executeScript runs code in web pages on demand."),
    RULE("native_messaging", Medium, "Talks to a native program", "Native messaging bridges the extension to a program on the computer."),
    RULE("dom.script_element", Medium, "Creates script elements", "document.createElement('script') is how remote code is injected into pages."),
    RULE("dom.dynamic_src", Low, "Assigns computed URLs to src attributes", "Sources set from variables can point anywhere."),
    RULE("dom.iframe_element", Low, "Creates iframes", "Injected frames can load third-party pages inside sites."),
    RULE("dom.inner_html", Low, "Writes HTML from variables", "innerHTML with computed content can inject markup and scripts."),
    RULE("content_script.keystrokes", Medium, "Content script listens to keystrokes or form input",
         "keydown, keypress, input or paste listeners in a content script can capture what you type."),
    RULE("content_script.listeners", Low, "Content script listens to page events", "New submit, change, copy or unload listeners in a content script."),
    RULE("fingerprinting", Low, "Collects device fingerprint details", "Language, time zone, user agent or screen size are read; combined with a new server this is targeting logic."),
    RULE("externally_connectable.widened", High, "Websites can message the extension",
         "externally_connectable now lets pages send messages to the extension, turning it into a bridge for those sites."),
    RULE("csp.loosened", Medium, "Weakens its own content security policy", "unsafe-eval, wasm-unsafe-eval or remote sources were added to the extension CSP."),
    RULE("update_url.changed", High, "Updates from a different server", "The update URL moved away from the store, so future versions come from elsewhere."),
    RULE("publisher.changed", High, "Web Store publisher changed", "The listing is offered by a different developer than before. Extensions that turn malicious are usually sold first."),
    RULE("store.removed", Medium, "Removed from the Web Store", "The listing disappeared, often because Google took it down for policy violations, while the installed copy keeps running."),
    RULE("key.changed", High, "Signing key changed", "A different key means a different publisher signed this version."),
    RULE("key.mismatch", High, "Files were not signed for this ID", "The key in manifest.json does not derive to the extension ID; the files were tampered with or sideloaded."),
    RULE("obfuscation.increased", Medium, "Code became obfuscated", "Long encoded strings, hex escapes, atob/fromCharCode or _0x identifiers appeared."),
    RULE("dnr.rules_added", Low, "Adds network rules", "New static declarativeNetRequest rules."),
    RULE("web_accessible_resources.changed", Low, "Exposes resources to websites", "web_accessible_resources changed; pages can load these files."),
    RULE("size.large_change", Low, "Package size changed a lot", "Total code size grew or shrank by more than half."),
    RULE("files.changed", Info, "Files added or removed", "New or deleted files in the package."),
    RULE("manifest.name_changed", Low, "Name changed", "The extension presents itself under a different name."),
    RULE("manifest.version", Info, "Version changed", "Routine version bump."),
    RULE("manifest.changed", Info, "Manifest fields changed", "Description, icons, background or other fields changed."),
};

#undef RULE

const RuleInfo& rule(const char* id) {
    const QString wanted = QString::fromLatin1(id);
    for (const RuleInfo& r : kRules) {
        if (r.id == wanted) {
            return r;
        }
    }
    return kRules.last();
}

Finding make(const char* id, const QString& detail, const QString& file = QString(), int line = 0,
             std::optional<Severity> override = std::nullopt) {
    const RuleInfo& r = rule(id);
    Finding f;
    f.rule = r.id;
    f.severity = override.value_or(r.severity);
    f.title = r.title;
    f.detail = detail;
    f.file = file;
    f.line = line;
    return f;
}

bool isBroadPattern(const QString& p) {
    static const QSet<QString> broad = {
        QStringLiteral("<all_urls>"),  QStringLiteral("*://*/*"),   QStringLiteral("http://*/*"),
        QStringLiteral("https://*/*"), QStringLiteral("*://*/"),    QStringLiteral("file:///*"),
        QStringLiteral("ws://*/*"),    QStringLiteral("wss://*/*"),
    };
    return broad.contains(p.trimmed());
}

QStringList newItems(const QStringList& before, const QStringList& after) {
    QStringList out;
    for (const QString& a : after) {
        if (!before.contains(a)) {
            out.append(a);
        }
    }
    return out;
}

const QSet<QString>& sensitivePermissions() {
    static const QSet<QString> s = {
        QStringLiteral("cookies"),         QStringLiteral("history"),        QStringLiteral("webRequest"),
        QStringLiteral("webRequestBlocking"), QStringLiteral("webRequestAuthProvider"),
        QStringLiteral("tabs"),            QStringLiteral("scripting"),      QStringLiteral("declarativeNetRequest"),
        QStringLiteral("declarativeNetRequestWithHostAccess"), QStringLiteral("declarativeNetRequestFeedback"),
        QStringLiteral("management"),      QStringLiteral("nativeMessaging"), QStringLiteral("debugger"),
        QStringLiteral("proxy"),           QStringLiteral("privacy"),        QStringLiteral("clipboardRead"),
        QStringLiteral("identity"),        QStringLiteral("identity.email"), QStringLiteral("downloads"),
        QStringLiteral("downloads.open"),  QStringLiteral("bookmarks"),      QStringLiteral("browsingData"),
        QStringLiteral("contentSettings"), QStringLiteral("geolocation"),    QStringLiteral("pageCapture"),
        QStringLiteral("desktopCapture"),  QStringLiteral("tabCapture"),     QStringLiteral("webNavigation"),
        QStringLiteral("sessions"),        QStringLiteral("topSites"),       QStringLiteral("userScripts"),
        QStringLiteral("enterprise.deviceAttributes"), QStringLiteral("enterprise.platformKeys"),
        QStringLiteral("certificateProvider"), QStringLiteral("vpnProvider"), QStringLiteral("webAuthenticationProxy"),
    };
    return s;
}

QString joinLimited(const QStringList& items, int max = 6) {
    if (items.size() <= max) {
        return items.join(QStringLiteral(", "));
    }
    return items.mid(0, max).join(QStringLiteral(", ")) +
           QStringLiteral(" and %1 more").arg(items.size() - max);
}

QString humanPeriod(qint64 ms) {
    if (ms <= 0) {
        return QStringLiteral("a timer");
    }
    if (ms % 3600000 == 0) {
        return QStringLiteral("every %1 h").arg(ms / 3600000);
    }
    if (ms % 60000 == 0) {
        return QStringLiteral("every %1 min").arg(ms / 60000);
    }
    if (ms >= 1000) {
        return QStringLiteral("every %1 s").arg(ms / 1000);
    }
    return QStringLiteral("every %1 ms").arg(ms);
}

QStringList allHostPatterns(const Signature& s) {
    QStringList out = s.manifest.hostPermissions;
    for (const ContentScript& cs : s.manifest.contentScripts) {
        out += cs.matches;
    }
    out.removeDuplicates();
    return out;
}

// Sinks that turn a string into running code. Creating script elements or assigning src is
// how every bundler loads chunks, so those do not count for the storage-to-exec chain.
bool sinkIsExec(const QString& kind) {
    return kind == QStringLiteral("eval") || kind == QStringLiteral("new_function") ||
           kind == QStringLiteral("timer_string") || kind == QStringLiteral("attribute_exec") ||
           kind == QStringLiteral("javascript_url");
}

bool sinkIsNetwork(const QString& kind) {
    return kind == QStringLiteral("fetch") || kind == QStringLiteral("xhr") ||
           kind == QStringLiteral("websocket") || kind == QStringLiteral("beacon") ||
           kind == QStringLiteral("event_source");
}

}  // namespace

const QList<RuleInfo>& allRules() {
    return kRules;
}

Finding findingForRule(const QString& ruleId, const QString& detail) {
    for (const RuleInfo& r : kRules) {
        if (r.id == ruleId) {
            Finding f;
            f.rule = r.id;
            f.severity = r.severity;
            f.title = r.title;
            f.detail = detail;
            return f;
        }
    }
    Finding f;
    f.rule = ruleId;
    f.title = ruleId;
    f.detail = detail;
    return f;
}

bool isAllowlistedHost(const QString& host, const ManifestFacts& manifest) {
    static const QStringList suffixes = {
        QStringLiteral("google.com"),        QStringLiteral("googleapis.com"),
        QStringLiteral("gstatic.com"),       QStringLiteral("googleusercontent.com"),
        QStringLiteral("youtube.com"),       QStringLiteral("chromium.org"),
        QStringLiteral("github.com"),        QStringLiteral("githubusercontent.com"),
        QStringLiteral("github.io"),         QStringLiteral("jsdelivr.net"),
        QStringLiteral("cdnjs.cloudflare.com"), QStringLiteral("unpkg.com"),
        QStringLiteral("mozilla.org"),       QStringLiteral("microsoft.com"),
        QStringLiteral("w3.org"),            QStringLiteral("schema.org"),
        QStringLiteral("wikipedia.org"),     QStringLiteral("wikimedia.org"),
        QStringLiteral("example.com"),       QStringLiteral("example.org"),
    };
    for (const QString& s : suffixes) {
        if (host == s || host.endsWith(u'.' + s)) {
            return true;
        }
    }
    const QString home = QUrl(manifest.homepageUrl).host().toLower();
    if (!home.isEmpty() && (host == home || host.endsWith(u'.' + home) || home.endsWith(u'.' + host))) {
        return true;
    }
    return false;
}

QList<Finding> compareSignatures(const Signature& before, const Signature& after) {
    QList<Finding> out;
    const bool baseline = before.isEmpty();
    const ManifestFacts& bm = before.manifest;
    const ManifestFacts& am = after.manifest;

    // --- hosts and content scripts
    const QStringList newHosts = newItems(allHostPatterns(before), allHostPatterns(after));
    QStringList broad;
    QStringList narrow;
    for (const QString& h : newHosts) {
        (isBroadPattern(h) ? broad : narrow).append(h);
    }
    if (!broad.isEmpty()) {
        QString detail = QStringLiteral("%1 grants access to every site.").arg(joinLimited(broad));
        if (!narrow.isEmpty()) {
            detail += QStringLiteral(" Also listed: %1.").arg(joinLimited(narrow));
        }
        out.append(make("host.all_urls", detail));
    } else if (!narrow.isEmpty()) {
        out.append(make("host.broadened", QStringLiteral("%1host patterns: %2.").arg(baseline ? QString() : QStringLiteral("New "), joinLimited(narrow)),
                        QString(), 0, baseline ? std::optional<Severity>(Severity::Low) : std::nullopt));
    }
    {
        bool allFramesBefore = false;
        bool startBefore = false;
        for (const ContentScript& cs : bm.contentScripts) {
            allFramesBefore = allFramesBefore || cs.allFrames;
            startBefore = startBefore || cs.runAt == QStringLiteral("document_start");
        }
        QStringList changes;
        for (const ContentScript& cs : am.contentScripts) {
            if (cs.allFrames && !allFramesBefore) {
                changes.append(QStringLiteral("runs in all frames"));
                allFramesBefore = true;
            }
            if (cs.runAt == QStringLiteral("document_start") && !startBefore) {
                changes.append(QStringLiteral("runs at document_start"));
                startBefore = true;
            }
        }
        const QStringList newCsFiles = newItems(before.contentScriptFiles, after.contentScriptFiles);
        if (!newCsFiles.isEmpty() && !baseline) {
            changes.append(QStringLiteral("new content script files: %1").arg(joinLimited(newCsFiles)));
        }
        if (!changes.isEmpty()) {
            out.append(make("content_scripts.broadened", changes.join(QStringLiteral("; ")) + u'.'));
        }
    }

    // --- permissions
    {
        const QStringList added = newItems(bm.permissions, am.permissions);
        QStringList sensitive;
        QStringList plain;
        for (const QString& p : added) {
            (sensitivePermissions().contains(p) ? sensitive : plain).append(p);
        }
        if (!sensitive.isEmpty()) {
            out.append(make("permission.sensitive", QStringLiteral("New permissions: %1.").arg(joinLimited(sensitive))));
        }
        if (!plain.isEmpty()) {
            out.append(make("permission.added", QStringLiteral("New permissions: %1.").arg(joinLimited(plain))));
        }
    }

    // --- externally connectable
    {
        const QStringList added = newItems(bm.externallyConnectableMatches, am.externallyConnectableMatches);
        if (!added.isEmpty()) {
            bool anyBroad = std::any_of(added.begin(), added.end(), isBroadPattern);
            out.append(make("externally_connectable.widened",
                            QStringLiteral("Pages matching %1 can now message the extension.").arg(joinLimited(added)),
                            QString(), 0, anyBroad ? Severity::High : Severity::Medium));
        }
    }

    // --- identity
    if (!after.keyMatchesId) {
        out.append(make("key.mismatch", QStringLiteral("The manifest key derives to a different ID than the install directory.")));
    }
    if (!baseline && !bm.key.isEmpty() && !am.key.isEmpty() && bm.key != am.key) {
        out.append(make("key.changed", QStringLiteral("manifest.json carries a different public key.")));
    }
    if (!baseline && bm.updateUrl != am.updateUrl) {
        const QString host = QUrl(am.updateUrl).host();
        const bool store = host.endsWith(QStringLiteral("google.com")) ||
                           host.endsWith(QStringLiteral("microsoft.com")) || am.updateUrl.isEmpty();
        out.append(make("update_url.changed",
                        QStringLiteral("update_url changed from \"%1\" to \"%2\".").arg(bm.updateUrl, am.updateUrl),
                        QString(), 0, store ? Severity::Medium : Severity::High));
    }

    // --- code execution sinks
    auto newSinksOfKinds = [&](const QStringList& kinds) {
        QList<Sink> found;
        for (const QString& k : kinds) {
            if (!before.hasSink(k)) {
                found += after.sinksOfKind(k);
            }
        }
        return found;
    };
    auto firstRef = [](const QList<Sink>& sinks, QString& file, int& line) {
        if (!sinks.isEmpty()) {
            file = sinks.first().file;
            line = sinks.first().line;
        }
    };
    {
        const QList<Sink> ev = newSinksOfKinds({QStringLiteral("eval"), QStringLiteral("new_function"), QStringLiteral("timer_string")});
        if (!ev.isEmpty()) {
            QString file; int line = 0; firstRef(ev, file, line);
            out.append(make("remote_code.eval", QStringLiteral("%1 occurrence(s), first: %2").arg(ev.size()).arg(ev.first().evidence), file, line));
        }
    }
    {
        const QList<Sink> ae = newSinksOfKinds({QStringLiteral("attribute_exec")});
        if (!ae.isEmpty()) {
            QString file; int line = 0; firstRef(ae, file, line);
            out.append(make("remote_code.attribute_exec", QStringLiteral("%1 occurrence(s), first: %2").arg(ae.size()).arg(ae.first().evidence), file, line));
        }
    }
    {
        const QList<Sink> remote = newSinksOfKinds({QStringLiteral("import_scripts_remote")});
        if (!remote.isEmpty()) {
            QString file; int line = 0; firstRef(remote, file, line);
            out.append(make("remote_code.import_scripts", remote.first().evidence, file, line));
        }
        const QList<Sink> dyn = newSinksOfKinds({QStringLiteral("import_scripts_dynamic")});
        if (!dyn.isEmpty()) {
            QString file; int line = 0; firstRef(dyn, file, line);
            out.append(make("remote_code.import_scripts_dynamic", dyn.first().evidence, file, line));
        }
    }
    {
        const QStringList srcs = newItems(before.remoteScriptSources, after.remoteScriptSources);
        if (!srcs.isEmpty()) {
            out.append(make("remote_code.html_script", QStringLiteral("Remote scripts: %1.").arg(joinLimited(srcs))));
        }
    }
    {
        const QList<Sink> js = newSinksOfKinds({QStringLiteral("javascript_url")});
        if (!js.isEmpty()) {
            QString file; int line = 0; firstRef(js, file, line);
            out.append(make("remote_code.javascript_url", js.first().evidence, file, line));
        }
    }
    // storage -> exec chains per file
    {
        QSet<QString> beforeChains;
        auto chains = [&](const Signature& s) {
            QSet<QString> files;
            for (const Sink& a : s.sinks) {
                if (a.kind != QStringLiteral("storage_get")) {
                    continue;
                }
                for (const Sink& b : s.sinksInFile(a.file)) {
                    if (sinkIsExec(b.kind)) {
                        files.insert(a.file);
                    }
                }
            }
            return files;
        };
        beforeChains = chains(before);
        const QSet<QString> afterChains = chains(after);
        for (const QString& file : afterChains) {
            if (beforeChains.contains(file)) {
                continue;
            }
            int line = 0;
            for (const Sink& s : after.sinksInFile(file)) {
                if (sinkIsExec(s.kind)) {
                    line = s.line;
                    break;
                }
            }
            out.append(make("remote_code.storage_to_exec",
                            QStringLiteral("%1 reads chrome.storage and executes string content.").arg(file), file, line));
        }
    }

    // --- headers
    {
        QStringList beforeHeaders;
        for (const DnrHeaderMod& h : before.headerMods) {
            beforeHeaders.append(h.header);
        }
        QStringList newHeaders;
        for (const DnrHeaderMod& h : after.headerMods) {
            const QString desc = QStringLiteral("%1 (%2)").arg(h.header, h.operation.isEmpty() ? QStringLiteral("modify") : h.operation);
            if (!beforeHeaders.contains(h.header) && !newHeaders.contains(desc)) {
                newHeaders.append(desc);
            }
        }
        if (!newHeaders.isEmpty()) {
            out.append(make("headers.strip_security", QStringLiteral("Static rules touch %1.").arg(joinLimited(newHeaders))));
        }
        // dynamic: rule updates / header listeners next to security header names in the same file
        QSet<QString> beforeDynamic;
        auto dynamicFiles = [&](const Signature& s) {
            QSet<QString> files;
            for (const Sink& k : s.sinks) {
                if ((k.kind == QStringLiteral("dnr_dynamic_rules") || k.kind == QStringLiteral("webrequest_headers")) &&
                    s.securityHeaderFiles.contains(k.file)) {
                    files.insert(k.file);
                }
            }
            return files;
        };
        beforeDynamic = dynamicFiles(before);
        for (const QString& file : dynamicFiles(after)) {
            if (!beforeDynamic.contains(file)) {
                out.append(make("headers.strip_security", QStringLiteral("%1 rewrites security headers at runtime (%2).").arg(file, joinLimited(after.securityHeaderLiterals)), file));
            }
        }
        const QList<Sink> dyn = newSinksOfKinds({QStringLiteral("dnr_dynamic_rules"), QStringLiteral("webrequest_headers")});
        if (!dyn.isEmpty() && dynamicFiles(after).isEmpty()) {
            QString file; int line = 0; firstRef(dyn, file, line);
            out.append(make("headers.dynamic_rules", dyn.first().evidence, file, line));
        }
    }

    // --- other capability sinks
    {
        const QList<Sink> ex = newSinksOfKinds({QStringLiteral("execute_script")});
        if (!ex.isEmpty()) {
            QString file; int line = 0; firstRef(ex, file, line);
            out.append(make("scripting.execute", ex.first().evidence, file, line));
        }
        const QList<Sink> nm = newSinksOfKinds({QStringLiteral("native_messaging")});
        if (!nm.isEmpty()) {
            QString file; int line = 0; firstRef(nm, file, line);
            out.append(make("native_messaging", nm.first().evidence, file, line));
        }
        const QList<Sink> se = newSinksOfKinds({QStringLiteral("script_element")});
        if (!se.isEmpty()) {
            QString file; int line = 0; firstRef(se, file, line);
            out.append(make("dom.script_element", se.first().evidence, file, line));
        }
        const QList<Sink> ds = newSinksOfKinds({QStringLiteral("src_assignment"), QStringLiteral("src_remote_literal")});
        if (!ds.isEmpty()) {
            QString file; int line = 0; firstRef(ds, file, line);
            out.append(make("dom.dynamic_src", ds.first().evidence, file, line));
        }
        const QList<Sink> fr = newSinksOfKinds({QStringLiteral("iframe_element")});
        if (!fr.isEmpty()) {
            QString file; int line = 0; firstRef(fr, file, line);
            out.append(make("dom.iframe_element", fr.first().evidence, file, line));
        }
        const QList<Sink> ih = newSinksOfKinds({QStringLiteral("inner_html")});
        if (!ih.isEmpty()) {
            QString file; int line = 0; firstRef(ih, file, line);
            out.append(make("dom.inner_html", QStringLiteral("%1 occurrence(s), first: %2").arg(ih.size()).arg(ih.first().evidence), file, line));
        }
    }

    // --- network domains and pollers
    {
        const QStringList beforeHosts = before.domainHosts();
        QSet<QString> pollerFiles;
        for (const TimerRef& t : after.timers) {
            if (t.kind == QStringLiteral("setInterval") && t.ms >= 30000) {
                pollerFiles.insert(t.file);
            }
        }
        QStringList knownNew;
        QStringList unknownNew;
        for (const DomainRef& d : after.domains) {
            if (beforeHosts.contains(d.host)) {
                continue;
            }
            bool poller = false;
            qint64 period = 0;
            for (const CodeRef& r : d.refs) {
                if (pollerFiles.contains(r.file)) {
                    bool network = false;
                    for (const Sink& s : after.sinksInFile(r.file)) {
                        network = network || sinkIsNetwork(s.kind);
                    }
                    if (network) {
                        poller = true;
                        for (const TimerRef& t : after.timers) {
                            if (t.file == r.file && t.kind == QStringLiteral("setInterval") && t.ms > period) {
                                period = t.ms;
                            }
                        }
                    }
                }
            }
            if (poller && !isAllowlistedHost(d.host, am)) {
                const CodeRef& r = d.refs.first();
                out.append(make("network.poller", QStringLiteral("Contacts %1 %2 (%3:%4).").arg(d.host, humanPeriod(period), r.file).arg(r.line), r.file, r.line));
                continue;
            }
            (isAllowlistedHost(d.host, am) ? knownNew : unknownNew).append(d.host);
        }
        if (!unknownNew.isEmpty()) {
            QString file;
            int line = 0;
            for (const DomainRef& d : after.domains) {
                if (d.host == unknownNew.first() && !d.refs.isEmpty()) {
                    file = d.refs.first().file;
                    line = d.refs.first().line;
                }
            }
            out.append(make("network.domain", QStringLiteral("New domains: %1.").arg(joinLimited(unknownNew)), file, line));
        }
        if (!knownNew.isEmpty()) {
            out.append(make("network.domain_known", QStringLiteral("New domains: %1.").arg(joinLimited(knownNew))));
        }
        if (after.dynamicUrls && !before.dynamicUrls) {
            out.append(make("network.dynamic_url", QStringLiteral("Request URLs are assembled from variables.")));
        }
    }

    // --- content script listeners
    {
        QSet<QString> beforeEvents;
        for (const ListenerRef& l : before.listeners) {
            if (before.contentScriptFiles.contains(l.file)) {
                beforeEvents.insert(l.event);
            }
        }
        QStringList keys;
        QStringList others;
        QString file;
        int line = 0;
        for (const ListenerRef& l : after.listeners) {
            if (!after.contentScriptFiles.contains(l.file) || beforeEvents.contains(l.event)) {
                continue;
            }
            const bool key = l.event == QStringLiteral("keydown") || l.event == QStringLiteral("keypress") ||
                             l.event == QStringLiteral("keyup") || l.event == QStringLiteral("input") ||
                             l.event == QStringLiteral("paste");
            QStringList& target = key ? keys : others;
            if (!target.contains(l.event)) {
                target.append(l.event);
                if (file.isEmpty()) {
                    file = l.file;
                    line = l.line;
                }
            }
        }
        if (!keys.isEmpty()) {
            out.append(make("content_script.keystrokes", QStringLiteral("Listens to %1 on web pages.").arg(joinLimited(keys)), file, line));
        }
        if (!others.isEmpty()) {
            out.append(make("content_script.listeners", QStringLiteral("Listens to %1 on web pages.").arg(joinLimited(others)), file, line));
        }
    }

    // --- fingerprinting
    {
        const QStringList added = newItems(before.fingerprinting, after.fingerprinting);
        if (!added.isEmpty()) {
            const bool withNewDomain = std::any_of(out.begin(), out.end(), [](const Finding& f) {
                return f.rule == QStringLiteral("network.domain") || f.rule == QStringLiteral("network.poller");
            });
            out.append(make("fingerprinting", QStringLiteral("Reads %1.").arg(joinLimited(added)),
                            after.fingerprintingFiles.value(0), 0,
                            withNewDomain ? Severity::Medium : Severity::Low));
        }
    }

    // --- CSP
    if (bm.contentSecurityPolicy != am.contentSecurityPolicy && !am.contentSecurityPolicy.isUndefined()) {
        const QString text = QString::fromUtf8(QJsonDocument::fromVariant(am.contentSecurityPolicy.toVariant()).toJson(QJsonDocument::Compact)).toLower();
        const QString beforeText = QString::fromUtf8(QJsonDocument::fromVariant(bm.contentSecurityPolicy.toVariant()).toJson(QJsonDocument::Compact)).toLower();
        const bool loosened = (text.contains(QStringLiteral("unsafe-eval")) && !beforeText.contains(QStringLiteral("unsafe-eval"))) ||
                              (text.contains(QStringLiteral("http")) && !beforeText.contains(QStringLiteral("http")));
        if (loosened) {
            out.append(make("csp.loosened", QStringLiteral("Content security policy is now: %1").arg(text.left(160))));
        } else if (!baseline) {
            out.append(make("manifest.changed", QStringLiteral("content_security_policy changed.")));
        }
    }

    // --- obfuscation
    {
        const int delta = after.obfuscation.total() - before.obfuscation.total();
        const int idents = after.obfuscation.obfuscatorIdentifiers - before.obfuscation.obfuscatorIdentifiers;
        if (delta >= 8 || idents >= 5) {
            out.append(make("obfuscation.increased",
                            QStringLiteral("%1 long encoded strings, %2 hex-escaped strings, %3 atob/fromCharCode calls, %4 obfuscator identifiers.")
                                .arg(after.obfuscation.longBase64Literals).arg(after.obfuscation.hexEscapedStrings)
                                .arg(after.obfuscation.atobCalls + after.obfuscation.fromCharCodeCalls)
                                .arg(after.obfuscation.obfuscatorIdentifiers)));
        }
    }

    // --- DNR rules, WAR, size, files, manifest odds and ends
    if (after.dnrRuleCount > before.dnrRuleCount && after.headerMods.isEmpty()) {
        out.append(make("dnr.rules_added", QStringLiteral("%1 static rules (was %2).").arg(after.dnrRuleCount).arg(before.dnrRuleCount)));
    }
    if (!baseline && bm.webAccessibleResources != am.webAccessibleResources) {
        out.append(make("web_accessible_resources.changed", QStringLiteral("web_accessible_resources changed.")));
    }
    if (!baseline && before.totalBytes > 0 && after.totalBytes > 0) {
        const double ratio = static_cast<double>(after.totalBytes) / static_cast<double>(before.totalBytes);
        if ((ratio > 1.5 || ratio < 0.5) && qAbs(after.totalBytes - before.totalBytes) > 100 * 1024) {
            out.append(make("size.large_change", QStringLiteral("%1 KiB → %2 KiB.").arg(before.totalBytes / 1024).arg(after.totalBytes / 1024)));
        }
    }
    if (!baseline) {
        QStringList beforeFiles;
        QStringList afterFiles;
        for (const FileSummary& f : before.files) beforeFiles.append(f.path);
        for (const FileSummary& f : after.files) afterFiles.append(f.path);
        const QStringList added = newItems(beforeFiles, afterFiles);
        const QStringList removed = newItems(afterFiles, beforeFiles);
        if (!added.isEmpty() || !removed.isEmpty()) {
            QString detail;
            if (!added.isEmpty()) detail += QStringLiteral("Added: %1. ").arg(joinLimited(added));
            if (!removed.isEmpty()) detail += QStringLiteral("Removed: %1.").arg(joinLimited(removed));
            out.append(make("files.changed", detail.trimmed()));
        }
        if (bm.name != am.name && !am.name.isEmpty()) {
            out.append(make("manifest.name_changed", QStringLiteral("\"%1\" → \"%2\".").arg(bm.name, am.name)));
        }
        if (bm.version != am.version) {
            out.append(make("manifest.version", QStringLiteral("%1 → %2.").arg(bm.version, am.version)));
        }
        QStringList misc;
        if (bm.description != am.description) misc.append(QStringLiteral("description"));
        if (bm.backgroundServiceWorker != am.backgroundServiceWorker || bm.backgroundScripts != am.backgroundScripts) misc.append(QStringLiteral("background"));
        if (bm.iconPath != am.iconPath) misc.append(QStringLiteral("icons"));
        if (bm.manifestVersion != am.manifestVersion) misc.append(QStringLiteral("manifest_version"));
        if (bm.minimumChromeVersion != am.minimumChromeVersion) misc.append(QStringLiteral("minimum_chrome_version"));
        if (!misc.isEmpty()) {
            out.append(make("manifest.changed", QStringLiteral("Changed: %1.").arg(misc.join(QStringLiteral(", ")))));
        }
    }

    if (baseline) {
        static const QHash<QString, QString> profileTitles = {
            {QStringLiteral("host.all_urls"), QStringLiteral("Can read and change every website")},
            {QStringLiteral("host.broadened"), QStringLiteral("Can read and change specific websites")},
            {QStringLiteral("content_scripts.broadened"), QStringLiteral("Injects code into pages or frames")},
            {QStringLiteral("permission.sensitive"), QStringLiteral("Uses sensitive browser APIs")},
            {QStringLiteral("permission.added"), QStringLiteral("Uses browser APIs")},
            {QStringLiteral("network.domain"), QStringLiteral("Talks to these domains")},
            {QStringLiteral("network.domain_known"), QStringLiteral("Talks to well-known domains")},
            {QStringLiteral("externally_connectable.widened"), QStringLiteral("Websites can message the extension")},
            {QStringLiteral("dnr.rules_added"), QStringLiteral("Declares network rules")},
        };
        for (Finding& f : out) {
            if (const auto it = profileTitles.constFind(f.rule); it != profileTitles.constEnd()) {
                f.title = it.value();
            }
            f.detail.replace(QStringLiteral("New host access: "), QStringLiteral("Host access: "));
            f.detail.replace(QStringLiteral("New permissions: "), QStringLiteral("Permissions: "));
            f.detail.replace(QStringLiteral("New domains: "), QStringLiteral("Domains: "));
        }
    }

    auto rank = [](const Finding& f) {
        for (qsizetype i = 0; i < kRules.size(); ++i) {
            if (kRules.at(i).id == f.rule) {
                return static_cast<int>(i);
            }
        }
        return static_cast<int>(kRules.size());
    };
    std::stable_sort(out.begin(), out.end(), [&](const Finding& a, const Finding& b) {
        if (a.severity != b.severity) {
            return static_cast<int>(a.severity) > static_cast<int>(b.severity);
        }
        return rank(a) < rank(b);
    });
    return out;
}

QString findingsSummary(const QList<Finding>& findings, int maxItems) {
    QStringList parts;
    for (const Finding& f : findings) {
        if (f.severity < Severity::Low) {
            continue;
        }
        QString part = f.title;
        if (f.rule == QStringLiteral("network.poller") || f.rule == QStringLiteral("network.domain") ||
            f.rule == QStringLiteral("host.all_urls") || f.rule == QStringLiteral("permission.sensitive")) {
            part = f.detail;
            part.remove(QStringLiteral("New host access: "));
            part.remove(QStringLiteral("New domains: "));
            part.remove(QStringLiteral("New permissions: "));
            part.remove(QStringLiteral("Contacts "));
            if (part.endsWith(u'.')) {
                part.chop(1);
            }
            if (f.rule == QStringLiteral("host.all_urls")) {
                part = QStringLiteral("+host access ") + part;
            } else if (f.rule == QStringLiteral("network.domain")) {
                part = QStringLiteral("+talks to ") + part;
            } else if (f.rule == QStringLiteral("permission.sensitive")) {
                part = QStringLiteral("+permission ") + part;
            } else {
                part = QStringLiteral("polls ") + part.section(QStringLiteral(" ("), 0, 0);
            }
        }
        parts.append(part);
        if (parts.size() >= maxItems) {
            break;
        }
    }
    if (parts.isEmpty()) {
        return findings.isEmpty() ? QStringLiteral("no behavior changes detected")
                                  : QStringLiteral("routine changes only");
    }
    return parts.join(QStringLiteral(", "));
}

}  // namespace extwatch
