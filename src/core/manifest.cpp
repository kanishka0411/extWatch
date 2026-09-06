#include "core/manifest.h"

#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QRegularExpression>

#include "core/jsonutil.h"

namespace extwatch {

QString ContentScript::key() const {
    // Scripts plus styles plus match patterns: two declarations that inject the same file into
    // different sites are different declarations and must be compared with their own past.
    QStringList scripts = js + css;
    scripts.sort();
    QStringList sites = matches;
    sites.sort();
    return scripts.join(u'|') + QStringLiteral("@") + sites.join(u'|');
}

bool isMatchPattern(const QString& s) {
    return s == QStringLiteral("<all_urls>") || s.contains(QStringLiteral("://"));
}

QString resolveI18n(const QString& text, const QJsonObject& messages) {
    if (!text.contains(QStringLiteral("__MSG_"))) {
        return text;
    }
    static const QRegularExpression re(QStringLiteral("__MSG_([A-Za-z0-9_@]+)__"));
    QString out;
    qsizetype last = 0;
    QRegularExpressionMatchIterator it = re.globalMatch(text);
    while (it.hasNext()) {
        const QRegularExpressionMatch m = it.next();
        out += text.mid(last, m.capturedStart() - last);
        const QString wanted = m.captured(1);
        QString replacement = m.captured(0);
        for (auto mi = messages.begin(); mi != messages.end(); ++mi) {
            if (mi.key().compare(wanted, Qt::CaseInsensitive) == 0) {
                replacement = mi.value().toObject().value(QStringLiteral("message")).toString();
                break;
            }
        }
        out += replacement;
        last = m.capturedEnd();
    }
    out += text.mid(last);
    return out;
}

QJsonObject loadMessages(const QString& extensionDir, const QString& defaultLocale) {
    QStringList candidates;
    if (!defaultLocale.isEmpty()) {
        candidates << defaultLocale;
        QString swapped = defaultLocale;
        swapped.replace(u'-', u'_');
        if (swapped != defaultLocale) {
            candidates << swapped;
        }
        const qsizetype sep = defaultLocale.indexOf(u'_');
        if (sep > 0) {
            candidates << defaultLocale.left(sep);
        }
    }
    candidates << QStringLiteral("en") << QStringLiteral("en_US") << QStringLiteral("en_GB");
    const QDir locales(extensionDir + QStringLiteral("/_locales"));
    for (const QString& loc : candidates) {
        QFile f(locales.filePath(loc + QStringLiteral("/messages.json")));
        if (!f.exists() || !f.open(QIODevice::ReadOnly)) {
            continue;
        }
        QByteArray data = f.readAll();
        if (data.startsWith("\xEF\xBB\xBF")) {
            data.remove(0, 3);
        }
        const QJsonDocument doc = QJsonDocument::fromJson(data);
        if (doc.isObject()) {
            return doc.object();
        }
    }
    return {};
}

namespace {

ContentScript parseContentScript(const QJsonObject& o) {
    ContentScript cs;
    cs.matches = toStringList(o.value(QStringLiteral("matches")));
    cs.excludeMatches = toStringList(o.value(QStringLiteral("exclude_matches")));
    cs.js = toStringList(o.value(QStringLiteral("js")));
    cs.css = toStringList(o.value(QStringLiteral("css")));
    cs.includeGlobs = toStringList(o.value(QStringLiteral("include_globs")));
    cs.excludeGlobs = toStringList(o.value(QStringLiteral("exclude_globs")));
    cs.runAt = o.value(QStringLiteral("run_at")).toString();
    cs.world = o.value(QStringLiteral("world")).toString().toUpper();
    cs.allFrames = o.value(QStringLiteral("all_frames")).toBool(false);
    cs.matchAboutBlank = o.value(QStringLiteral("match_about_blank")).toBool(false);
    cs.matchOriginAsFallback = o.value(QStringLiteral("match_origin_as_fallback")).toBool(false);
    return cs;
}

QJsonObject contentScriptToJson(const ContentScript& cs) {
    QJsonObject o;
    o.insert(QStringLiteral("matches"), fromStringList(cs.matches));
    if (!cs.excludeMatches.isEmpty()) {
        o.insert(QStringLiteral("exclude_matches"), fromStringList(cs.excludeMatches));
    }
    o.insert(QStringLiteral("js"), fromStringList(cs.js));
    if (!cs.css.isEmpty()) {
        o.insert(QStringLiteral("css"), fromStringList(cs.css));
    }
    if (!cs.includeGlobs.isEmpty()) {
        o.insert(QStringLiteral("include_globs"), fromStringList(cs.includeGlobs));
    }
    if (!cs.excludeGlobs.isEmpty()) {
        o.insert(QStringLiteral("exclude_globs"), fromStringList(cs.excludeGlobs));
    }
    if (!cs.runAt.isEmpty()) {
        o.insert(QStringLiteral("run_at"), cs.runAt);
    }
    if (!cs.world.isEmpty()) {
        o.insert(QStringLiteral("world"), cs.world);
    }
    o.insert(QStringLiteral("all_frames"), cs.allFrames);
    if (cs.matchOriginAsFallback) {
        o.insert(QStringLiteral("match_origin_as_fallback"), true);
    }
    return o;
}

// Permission arrays may contain objects (e.g. usbDevices); keep those as compact JSON text.
QStringList permissionEntries(const QJsonValue& value) {
    QStringList out;
    for (const QJsonValue& v : value.toArray()) {
        if (v.isString()) {
            out.append(v.toString());
        } else if (v.isObject() || v.isArray()) {
            out.append(QString::fromUtf8(QJsonDocument::fromVariant(v.toVariant())
                                             .toJson(QJsonDocument::Compact)));
        }
    }
    return out;
}

void splitHostPatterns(QStringList& permissions, QStringList& hosts) {
    QStringList kept;
    for (const QString& p : permissions) {
        if (isMatchPattern(p)) {
            hosts.append(p);
        } else {
            kept.append(p);
        }
    }
    permissions = kept;
}

}  // namespace

ManifestFacts parseManifest(const QJsonObject& m,
                            const std::function<QString(const QString&)>& i18n) {
    ManifestFacts f;
    f.valid = true;
    f.raw = m;
    f.manifestVersion = m.value(QStringLiteral("manifest_version")).toInt(0);
    f.name = i18n(m.value(QStringLiteral("name")).toString());
    f.shortName = i18n(m.value(QStringLiteral("short_name")).toString());
    f.description = i18n(m.value(QStringLiteral("description")).toString());
    f.version = m.value(QStringLiteral("version")).toString();
    f.versionName = m.value(QStringLiteral("version_name")).toString();
    f.defaultLocale = m.value(QStringLiteral("default_locale")).toString();
    f.key = m.value(QStringLiteral("key")).toString();
    f.updateUrl = m.value(QStringLiteral("update_url")).toString();
    f.homepageUrl = m.value(QStringLiteral("homepage_url")).toString();
    f.minimumChromeVersion = m.value(QStringLiteral("minimum_chrome_version")).toString();

    f.permissions = permissionEntries(m.value(QStringLiteral("permissions")));
    f.optionalPermissions = permissionEntries(m.value(QStringLiteral("optional_permissions")));
    f.hostPermissions = toStringList(m.value(QStringLiteral("host_permissions")));
    f.optionalHostPermissions = toStringList(m.value(QStringLiteral("optional_host_permissions")));
    // MV2 mixes host patterns into "permissions"; normalize so both versions compare alike.
    splitHostPatterns(f.permissions, f.hostPermissions);
    splitHostPatterns(f.optionalPermissions, f.optionalHostPermissions);

    for (const QJsonValue& v : m.value(QStringLiteral("content_scripts")).toArray()) {
        if (v.isObject()) {
            f.contentScripts.append(parseContentScript(v.toObject()));
        }
    }

    const QJsonObject bg = m.value(QStringLiteral("background")).toObject();
    f.backgroundServiceWorker = bg.value(QStringLiteral("service_worker")).toString();
    f.backgroundScripts = toStringList(bg.value(QStringLiteral("scripts")));
    f.backgroundPage = bg.value(QStringLiteral("page")).toString();
    if (bg.contains(QStringLiteral("persistent"))) {
        f.backgroundPersistent = bg.value(QStringLiteral("persistent")).toBool(true);
    }

    if (m.contains(QStringLiteral("externally_connectable"))) {
        f.externallyConnectablePresent = true;
        const QJsonObject ec = m.value(QStringLiteral("externally_connectable")).toObject();
        f.externallyConnectableMatches = toStringList(ec.value(QStringLiteral("matches")));
        f.externallyConnectableIds = toStringList(ec.value(QStringLiteral("ids")));
    }

    f.webAccessibleResources = m.value(QStringLiteral("web_accessible_resources"));
    f.contentSecurityPolicy = m.value(QStringLiteral("content_security_policy"));

    const QJsonObject dnr = m.value(QStringLiteral("declarative_net_request")).toObject();
    for (const QJsonValue& v : dnr.value(QStringLiteral("rule_resources")).toArray()) {
        const QJsonObject o = v.toObject();
        f.dnrRuleResources.append({o.value(QStringLiteral("id")).toString(),
                                   o.value(QStringLiteral("path")).toString(),
                                   o.value(QStringLiteral("enabled")).toBool(true)});
    }
    f.oauth2 = m.value(QStringLiteral("oauth2")).toObject();
    f.devtoolsPage = m.value(QStringLiteral("devtools_page")).toString();
    f.sandbox = m.value(QStringLiteral("sandbox")).toObject();

    const QJsonObject icons = m.value(QStringLiteral("icons")).toObject();
    int best = -1;
    for (auto it = icons.begin(); it != icons.end(); ++it) {
        const int size = it.key().toInt();
        if (size > best && it.value().isString()) {
            best = size;
            f.iconPath = it.value().toString();
        }
    }
    return f;
}

ManifestFacts readManifest(const QString& extensionDir) {
    ManifestFacts f;
    QFile file(extensionDir + QStringLiteral("/manifest.json"));
    if (!file.open(QIODevice::ReadOnly)) {
        f.error = QStringLiteral("cannot open manifest.json: %1").arg(file.errorString());
        return f;
    }
    QByteArray data = file.readAll();
    if (data.startsWith("\xEF\xBB\xBF")) {
        data.remove(0, 3);
    }
    QJsonParseError parseError;
    const QJsonDocument doc = QJsonDocument::fromJson(data, &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
        f.error = QStringLiteral("cannot parse manifest.json: %1").arg(parseError.errorString());
        return f;
    }
    const QJsonObject m = doc.object();
    const QJsonObject messages =
        loadMessages(extensionDir, m.value(QStringLiteral("default_locale")).toString());
    return parseManifest(m, [&messages](const QString& s) { return resolveI18n(s, messages); });
}

QJsonObject ManifestFacts::toJson() const {
    QJsonObject o;
    o.insert(QStringLiteral("manifest_version"), manifestVersion);
    o.insert(QStringLiteral("name"), name);
    if (!shortName.isEmpty()) {
        o.insert(QStringLiteral("short_name"), shortName);
    }
    o.insert(QStringLiteral("description"), description);
    o.insert(QStringLiteral("version"), version);
    if (!versionName.isEmpty()) {
        o.insert(QStringLiteral("version_name"), versionName);
    }
    if (!defaultLocale.isEmpty()) {
        o.insert(QStringLiteral("default_locale"), defaultLocale);
    }
    o.insert(QStringLiteral("has_key"), !key.isEmpty());
    o.insert(QStringLiteral("update_url"), updateUrl);
    if (!homepageUrl.isEmpty()) {
        o.insert(QStringLiteral("homepage_url"), homepageUrl);
    }
    if (!minimumChromeVersion.isEmpty()) {
        o.insert(QStringLiteral("minimum_chrome_version"), minimumChromeVersion);
    }
    o.insert(QStringLiteral("permissions"), fromStringList(permissions));
    o.insert(QStringLiteral("optional_permissions"), fromStringList(optionalPermissions));
    o.insert(QStringLiteral("host_permissions"), fromStringList(hostPermissions));
    o.insert(QStringLiteral("optional_host_permissions"), fromStringList(optionalHostPermissions));
    QJsonArray scripts;
    for (const ContentScript& cs : contentScripts) {
        scripts.append(contentScriptToJson(cs));
    }
    o.insert(QStringLiteral("content_scripts"), scripts);
    QJsonObject bg;
    if (!backgroundServiceWorker.isEmpty()) {
        bg.insert(QStringLiteral("service_worker"), backgroundServiceWorker);
    }
    if (!backgroundScripts.isEmpty()) {
        bg.insert(QStringLiteral("scripts"), fromStringList(backgroundScripts));
    }
    if (!backgroundPage.isEmpty()) {
        bg.insert(QStringLiteral("page"), backgroundPage);
    }
    if (backgroundPersistent.has_value()) {
        bg.insert(QStringLiteral("persistent"), *backgroundPersistent);
    }
    o.insert(QStringLiteral("background"), bg);
    if (externallyConnectablePresent) {
        QJsonObject ec;
        ec.insert(QStringLiteral("matches"), fromStringList(externallyConnectableMatches));
        ec.insert(QStringLiteral("ids"), fromStringList(externallyConnectableIds));
        o.insert(QStringLiteral("externally_connectable"), ec);
    }
    if (!webAccessibleResources.isUndefined()) {
        o.insert(QStringLiteral("web_accessible_resources"), webAccessibleResources);
    }
    if (!contentSecurityPolicy.isUndefined()) {
        o.insert(QStringLiteral("content_security_policy"), contentSecurityPolicy);
    }
    if (!dnrRuleResources.isEmpty()) {
        QJsonArray rules;
        for (const RuleResource& r : dnrRuleResources) {
            QJsonObject ro;
            ro.insert(QStringLiteral("id"), r.id);
            ro.insert(QStringLiteral("path"), r.path);
            ro.insert(QStringLiteral("enabled"), r.enabled);
            rules.append(ro);
        }
        o.insert(QStringLiteral("dnr_rule_resources"), rules);
    }
    if (!oauth2.isEmpty()) {
        o.insert(QStringLiteral("oauth2"), oauth2);
    }
    if (!devtoolsPage.isEmpty()) {
        o.insert(QStringLiteral("devtools_page"), devtoolsPage);
    }
    if (!sandbox.isEmpty()) {
        o.insert(QStringLiteral("sandbox"), sandbox);
    }
    if (!iconPath.isEmpty()) {
        o.insert(QStringLiteral("icon"), iconPath);
    }
    return o;
}

}  // namespace extwatch
