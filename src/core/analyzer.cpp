#include "core/analyzer.h"

#include <QDateTime>
#include <QFile>
#include <QJsonDocument>
#include <QSet>
#include <QTimeZone>
#include <algorithm>

#include "core/prettify.h"
#include "extwatch/version.h"

namespace extwatch {

QList<SourceFile> loadSourcesFromArchive(Database& db, const BlobStore& blobs, qint64 versionId,
                                         bool contentForAll) {
    QList<SourceFile> out;
    qint64 loaded = 0;
    for (const FileEntry& f : db.filesForVersion(versionId)) {
        SourceFile file;
        file.path = f.relPath;
        file.size = f.size;
        const bool wanted = contentForAll || isAnalyzablePath(f.relPath);
        if (wanted && (contentForAll || (f.size <= kMaxAnalyzedBytes && loaded + f.size <= kMaxLoadedBytes))) {
            loaded += f.size;
            QFile blob(blobs.pathFor(f.sha256));
            if (!blob.open(QIODevice::ReadOnly)) {
                continue;
            }
            file.content = blob.readAll();
        }
        out.append(file);
    }
    return out;
}

std::optional<Signature> signatureForVersion(Database& db, const BlobStore& blobs, qint64 versionId) {
    const std::optional<VersionRow> row = db.versionById(versionId);
    if (!row) {
        return std::nullopt;
    }
    if (!row->signatureJson.isEmpty()) {
        const QJsonObject json = QJsonDocument::fromJson(row->signatureJson.toUtf8()).object();
        // Only a signature produced by the current analyzer is reused; anything older is
        // recomputed from the immutable blobs so old and new versions are compared like for like.
        if (json.value(QStringLiteral("schema")).toInt() == kSignatureSchema) {
            return Signature::fromJson(json);
        }
    }
    const QList<SourceFile> files = loadSourcesFromArchive(db, blobs, versionId, false);
    ManifestFacts manifest;
    for (const SourceFile& f : files) {
        if (f.path == QStringLiteral("manifest.json")) {
            const QJsonObject obj = QJsonDocument::fromJson(f.content).object();
            // Resolve names through the archived _locales.
            QJsonObject messages;
            const QString locale = obj.value(QStringLiteral("default_locale")).toString();
            for (const QString& candidate : {locale, QStringLiteral("en"), QStringLiteral("en_US")}) {
                if (candidate.isEmpty()) {
                    continue;
                }
                for (const SourceFile& m : files) {
                    if (m.path == QStringLiteral("_locales/%1/messages.json").arg(candidate)) {
                        messages = QJsonDocument::fromJson(m.content).object();
                    }
                }
                if (!messages.isEmpty()) {
                    break;
                }
            }
            manifest = parseManifest(obj, [&messages](const QString& s) { return resolveI18n(s, messages); });
        }
    }
    const std::optional<ExtensionRow> ext = db.extensionById(row->extensionId);
    Signature sig = buildSignature(manifest, files, ext ? ext->extId : QString());
    sig.version = row->version;
    db.setSignature(versionId, QString::fromUtf8(QJsonDocument(sig.toJson()).toJson(QJsonDocument::Compact)));
    return sig;
}

QList<Finding> analyzeEvent(Database& db, const BlobStore& blobs, qint64 eventId) {
    const std::optional<EventRow> ev = db.eventById(eventId);
    if (!ev || !ev->toVersionId) {
        return {};
    }
    const std::optional<Signature> to = signatureForVersion(db, blobs, *ev->toVersionId);
    if (!to) {
        return {};
    }
    Signature from;
    if (ev->fromVersionId) {
        if (const std::optional<Signature> f = signatureForVersion(db, blobs, *ev->fromVersionId)) {
            from = *f;
        }
    }
    const QList<Finding> findings = compareSignatures(from, *to);
    db.setEventFindings(eventId, severityId(maxSeverity(findings)),
                        QString::fromUtf8(QJsonDocument(findingsToJson(findings)).toJson(QJsonDocument::Compact)));
    return findings;
}

namespace {

QList<FileChange> fileChanges(const QList<FileEntry>& before, const QList<FileEntry>& after) {
    QHash<QString, const FileEntry*> beforeMap;
    for (const FileEntry& f : before) {
        beforeMap.insert(f.relPath, &f);
    }
    QSet<QString> seen;
    QList<FileChange> out;
    for (const FileEntry& f : after) {
        FileChange c;
        c.path = f.relPath;
        c.newBytes = f.size;
        seen.insert(f.relPath);
        if (const FileEntry* const* b = beforeMap.constFind(f.relPath) != beforeMap.constEnd()
                                            ? &beforeMap[f.relPath]
                                            : nullptr) {
            c.oldBytes = (*b)->size;
            c.status = (*b)->sha256 == f.sha256 ? FileChange::Status::Unchanged : FileChange::Status::Modified;
        } else {
            c.status = FileChange::Status::Added;
        }
        out.append(c);
    }
    for (const FileEntry& f : before) {
        if (!seen.contains(f.relPath)) {
            FileChange c;
            c.path = f.relPath;
            c.oldBytes = f.size;
            c.status = FileChange::Status::Removed;
            out.append(c);
        }
    }
    auto rank = [](FileChange::Status s) {
        switch (s) {
            case FileChange::Status::Modified: return 0;
            case FileChange::Status::Added: return 1;
            case FileChange::Status::Removed: return 2;
            case FileChange::Status::Unchanged: return 3;
        }
        return 4;
    };
    std::stable_sort(out.begin(), out.end(), [&](const FileChange& a, const FileChange& b) {
        const int ra = rank(a.status);
        const int rb = rank(b.status);
        return ra != rb ? ra < rb : a.path < b.path;
    });
    return out;
}

QString manifestText(const Signature& sig) {
    if (sig.manifest.raw.isEmpty()) {
        return {};
    }
    return QString::fromUtf8(QJsonDocument(sig.manifest.raw).toJson(QJsonDocument::Indented));
}

void fillCommon(Database& db, ChangeReport& report) {
    const std::optional<ExtensionRow> ext = db.extensionById(report.to.extensionId);
    if (ext) {
        report.extId = ext->extId;
        report.name = ext->name;
        if (const std::optional<ProfileRow> profile = db.profileById(ext->profileId)) {
            report.profileName = profile->displayName;
            if (const std::optional<BrowserRow> browser = db.browserById(profile->browserId)) {
                report.browserName = browser->displayName;
            }
        }
    }
    if (report.name.isEmpty()) {
        report.name = report.toSignature.manifest.name;
    }
}

}  // namespace

std::optional<ChangeReport> buildVersionReport(Database& db, const BlobStore& blobs,
                                               std::optional<qint64> fromVersionId, qint64 toVersionId) {
    const std::optional<VersionRow> to = db.versionById(toVersionId);
    if (!to) {
        return std::nullopt;
    }
    ChangeReport r;
    r.to = *to;
    r.eventKind = fromVersionId ? QStringLiteral("updated") : QStringLiteral("baseline");
    if (fromVersionId) {
        r.from = db.versionById(*fromVersionId);
    }
    const std::optional<Signature> toSig = signatureForVersion(db, blobs, toVersionId);
    if (!toSig) {
        return std::nullopt;
    }
    r.toSignature = *toSig;
    if (r.from) {
        if (const std::optional<Signature> fromSig = signatureForVersion(db, blobs, r.from->id)) {
            r.fromSignature = *fromSig;
        }
    }
    r.findings = compareSignatures(r.fromSignature, r.toSignature);
    r.files = fileChanges(r.from ? db.filesForVersion(r.from->id) : QList<FileEntry>(),
                          db.filesForVersion(toVersionId));
    const QStringList oldManifest = splitLines(manifestText(r.fromSignature));
    const QStringList newManifest = splitLines(manifestText(r.toSignature));
    r.manifestDiff = unifiedDiff(QStringLiteral("manifest.json (%1)").arg(r.from ? r.from->version : QStringLiteral("none")),
                                 QStringLiteral("manifest.json (%1)").arg(r.to.version),
                                 hunksFromDiff(diffLines(oldManifest, newManifest), 3));
    fillCommon(db, r);
    return r;
}

std::optional<ChangeReport> buildChangeReport(Database& db, const BlobStore& blobs, qint64 eventId) {
    const std::optional<EventRow> ev = db.eventById(eventId);
    if (!ev || !ev->toVersionId) {
        return std::nullopt;
    }
    std::optional<ChangeReport> r = buildVersionReport(db, blobs, ev->fromVersionId, *ev->toVersionId);
    if (!r) {
        return std::nullopt;
    }
    r->eventKind = ev->kind;
    r->eventAt = ev->at;
    // Findings are recomputed from the stored signatures so the view always reflects the current
    // rules; the stored copy (used for lists and notifications) is refreshed at the same time.
    db.setEventFindings(eventId, severityId(maxSeverity(r->findings)),
                        QString::fromUtf8(QJsonDocument(findingsToJson(r->findings)).toJson(QJsonDocument::Compact)));
    return r;
}

std::optional<QString> fileDisplayText(Database& db, const BlobStore& blobs, qint64 versionId,
                                       const QString& path) {
    for (const FileEntry& f : db.filesForVersion(versionId)) {
        if (f.relPath != path) {
            continue;
        }
        QFile blob(blobs.pathFor(f.sha256));
        if (!blob.open(QIODevice::ReadOnly)) {
            return std::nullopt;
        }
        return displayText(path, blob.readAll());
    }
    return std::nullopt;
}

namespace {

QString esc(const QString& s) {
    return s.toHtmlEscaped();
}

QString fmtDate(qint64 secs) {
    return secs > 0 ? QDateTime::fromSecsSinceEpoch(secs, QTimeZone::UTC).toString(Qt::ISODate) : QStringLiteral("-");
}

const char* const kReportCss = R"CSS(
:root{--bg:#0f1117;--panel:#171a23;--line:#262a36;--fg:#e6e8ee;--muted:#9aa3b5;--high:#ff5c5c;--medium:#ffb020;--low:#5aa9ff;--info:#8b93a7;--add:#1f3b2a;--addfg:#8ee59a;--del:#4a2126;--delfg:#ff9aa2;--ctx:#151823}
@media (prefers-color-scheme: light){:root{--bg:#fafbfd;--panel:#fff;--line:#e3e6ee;--fg:#1a1d26;--muted:#5b647a;--add:#e6f7ea;--addfg:#116329;--del:#fde8ea;--delfg:#a40e26;--ctx:#f6f7fa}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 24px 64px}h1{font-size:24px;margin:0 0 4px}h2{font-size:16px;margin:32px 0 12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.sub{color:var(--muted)}.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin:20px 0}.meta div{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}.meta b{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:4px}
.finding{display:grid;grid-template-columns:84px 1fr;gap:12px;padding:12px 14px;border:1px solid var(--line);border-radius:10px;background:var(--panel);margin-bottom:8px}.sev{font-weight:700;font-size:12px;text-transform:uppercase;letter-spacing:.06em;padding-top:2px}.sev.high{color:var(--high)}.sev.medium{color:var(--medium)}.sev.low{color:var(--low)}.sev.info{color:var(--info)}
.finding .t{font-weight:600}.finding .d{color:var(--muted)}.finding code{font-size:12px}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line)}th{color:var(--muted);font-weight:600}.st{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em}.st.modified{color:var(--medium)}.st.added{color:var(--addfg)}.st.removed{color:var(--delfg)}.st.unchanged{color:var(--muted)}
pre.diff{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:0;overflow:auto;font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;margin:0 0 16px}pre.diff div{padding:0 12px;white-space:pre}pre.diff .hunk{color:var(--muted);background:var(--ctx);padding:4px 12px}pre.diff .add{background:var(--add);color:var(--addfg)}pre.diff .del{background:var(--del);color:var(--delfg)}
details{margin-bottom:12px}summary{cursor:pointer;font-weight:600;padding:8px 0}footer{margin-top:40px;color:var(--muted);font-size:12px}
)CSS";

void appendHunks(QString& html, const QList<Hunk>& hunks) {
    html += QStringLiteral("<pre class=\"diff\">");
    for (const Hunk& h : hunks) {
        html += QStringLiteral("<div class=\"hunk\">@@ -%1,%2 +%3,%4 @@</div>").arg(h.oldStart).arg(h.oldCount).arg(h.newStart).arg(h.newCount);
        for (const DiffLine& l : h.lines) {
            const char* cls = l.kind == LineKind::Added ? "add" : l.kind == LineKind::Removed ? "del" : "ctx";
            const QChar prefix = l.kind == LineKind::Added ? u'+' : l.kind == LineKind::Removed ? u'-' : u' ';
            html += QStringLiteral("<div class=\"%1\">%2%3</div>").arg(QLatin1StringView(cls)).arg(prefix).arg(esc(l.text));
        }
    }
    html += QStringLiteral("</pre>");
}

}  // namespace

QString renderHtmlReport(Database& db, const BlobStore& blobs, const ChangeReport& r, int maxFiles,
                         int maxLinesPerFile) {
    QString html;
    html += QStringLiteral("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    html += QStringLiteral("<title>ExtWatch report: %1 %2</title><style>%3</style></head><body><main>")
                .arg(esc(r.name), esc(r.to.version), QLatin1StringView(kReportCss));
    const QString fromVersion = r.from ? r.from->version : QStringLiteral("(first snapshot)");
    html += QStringLiteral("<h1>%1</h1><div class=\"sub\">%2 &middot; %3 &rarr; <b>%4</b></div>")
                .arg(esc(r.name), esc(r.extId), esc(fromVersion), esc(r.to.version));
    html += QStringLiteral("<div class=\"meta\">");
    html += QStringLiteral("<div><b>Where</b>%1 / %2</div>").arg(esc(r.browserName), esc(r.profileName));
    html += QStringLiteral("<div><b>Event</b>%1 at %2</div>").arg(esc(r.eventKind), esc(fmtDate(r.eventAt)));
    html += QStringLiteral("<div><b>New version tree hash</b><code>sha256:%1</code></div>").arg(esc(r.to.treeHash));
    if (r.from) {
        html += QStringLiteral("<div><b>Old version tree hash</b><code>sha256:%1</code></div>").arg(esc(r.from->treeHash));
    }
    html += QStringLiteral("<div><b>Files</b>%1 files, %2 KiB</div>").arg(r.to.fileCount).arg(r.to.bytes / 1024);
    html += QStringLiteral("<div><b>Signed for this ID</b>%1</div>").arg(r.to.keyMatchesId ? QStringLiteral("yes") : QStringLiteral("NO"));
    html += QStringLiteral("</div>");

    html += QStringLiteral("<h2>Findings</h2>");
    if (r.findings.isEmpty()) {
        html += QStringLiteral("<p class=\"sub\">No behavior changes detected.</p>");
    }
    for (const Finding& f : r.findings) {
        html += QStringLiteral("<div class=\"finding\"><div class=\"sev %1\">%1</div><div><div class=\"t\">%2</div><div class=\"d\">%3")
                    .arg(severityId(f.severity), esc(f.title), esc(f.detail));
        if (!f.file.isEmpty()) {
            html += QStringLiteral(" <code>%1%2</code>").arg(esc(f.file), f.line > 0 ? QStringLiteral(":%1").arg(f.line) : QString());
        }
        html += QStringLiteral("</div></div></div>");
    }

    html += QStringLiteral("<h2>Manifest</h2>");
    if (r.manifestDiff.count(u'\n') <= 2) {
        html += QStringLiteral("<p class=\"sub\">manifest.json unchanged.</p>");
    } else {
        const QStringList oldManifest = splitLines(manifestText(r.fromSignature));
        const QStringList newManifest = splitLines(manifestText(r.toSignature));
        appendHunks(html, hunksFromDiff(diffLines(oldManifest, newManifest), 3));
    }

    html += QStringLiteral("<h2>Files</h2><table><tr><th>Status</th><th>Path</th><th>Old</th><th>New</th></tr>");
    for (const FileChange& c : r.files) {
        const char* st = c.status == FileChange::Status::Modified ? "modified" : c.status == FileChange::Status::Added ? "added" : c.status == FileChange::Status::Removed ? "removed" : "unchanged";
        html += QStringLiteral("<tr><td class=\"st %1\">%1</td><td><code>%2</code></td><td>%3</td><td>%4</td></tr>")
                    .arg(QLatin1StringView(st), esc(c.path))
                    .arg(c.oldBytes > 0 ? QStringLiteral("%1 B").arg(c.oldBytes) : QStringLiteral("-"))
                    .arg(c.newBytes > 0 ? QStringLiteral("%1 B").arg(c.newBytes) : QStringLiteral("-"));
    }
    html += QStringLiteral("</table>");

    html += QStringLiteral("<h2>Code changes</h2>");
    int shown = 0;
    for (const FileChange& c : r.files) {
        if (c.status == FileChange::Status::Unchanged || c.path == QStringLiteral("manifest.json")) {
            continue;
        }
        if (shown++ >= maxFiles) {
            html += QStringLiteral("<p class=\"sub\">More files changed than shown here. Run <code>extwatch diff</code> for the rest.</p>");
            break;
        }
        const std::optional<QString> oldText = r.from ? fileDisplayText(db, blobs, r.from->id, c.path) : std::nullopt;
        const std::optional<QString> newText = fileDisplayText(db, blobs, r.to.id, c.path);
        const QStringList oldLines = oldText ? splitLines(*oldText) : QStringList();
        const QStringList newLines = newText ? splitLines(*newText) : QStringList();
        if ((oldText && oldText->startsWith(QStringLiteral("[binary"))) || (newText && newText->startsWith(QStringLiteral("[binary")))) {
            html += QStringLiteral("<details><summary><code>%1</code> (binary)</summary></details>").arg(esc(c.path));
            continue;
        }
        const LineDiff diff = diffLines(oldLines, newLines);
        html += QStringLiteral("<details%1><summary><code>%2</code> &nbsp;<span class=\"sub\">+%3 &minus;%4</span></summary>")
                    .arg(shown <= 3 ? QStringLiteral(" open") : QString(), esc(c.path))
                    .arg(diff.added).arg(diff.removed);
        if (diff.truncated) {
            html += QStringLiteral("<p class=\"sub\">File too large to diff inline.</p>");
        } else {
            QList<Hunk> hunks = hunksFromDiff(diff, 3);
            int lines = 0;
            QList<Hunk> capped;
            for (const Hunk& h : hunks) {
                if (lines + h.lines.size() > maxLinesPerFile) {
                    break;
                }
                lines += static_cast<int>(h.lines.size());
                capped.append(h);
            }
            appendHunks(html, capped);
            if (capped.size() < hunks.size()) {
                html += QStringLiteral("<p class=\"sub\">%1 more hunks not shown.</p>").arg(hunks.size() - capped.size());
            }
        }
        html += QStringLiteral("</details>");
    }
    if (shown == 0) {
        html += QStringLiteral("<p class=\"sub\">No code files changed.</p>");
    }
    html += QStringLiteral("<footer>Generated by ExtWatch %1 &middot; rules v1 &middot; reproduce with <code>extwatch diff %2 %3 %4</code></footer>")
                .arg(QStringLiteral(EXTWATCH_VERSION), esc(r.extId), esc(fromVersion), esc(r.to.version));
    html += QStringLiteral("</main></body></html>");
    return html;
}

}  // namespace extwatch
