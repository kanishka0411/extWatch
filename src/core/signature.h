#pragma once

#include <QByteArray>
#include <QJsonObject>
#include <QList>
#include <QString>
#include <QStringList>

#include "core/jsanalysis.h"
#include "core/manifest.h"

namespace extwatch {

struct SourceFile {
    QString path;  // relative, forward slashes
    QByteArray content;  // may be empty for files that are not analyzed
    qint64 size = 0;     // size on disk, valid even when content was not loaded
};

// Files whose content the analysis reads: JavaScript, HTML and JSON.
bool isAnalyzablePath(const QString& path);

// A header modification declared in a static declarativeNetRequest ruleset.
struct DnrHeaderMod {
    QString ruleset;
    int ruleId = 0;
    QString header;     // lower-case
    QString operation;  // remove, set, append
};

struct FileSummary {
    QString path;
    qint64 bytes = 0;
    bool analyzed = false;
    int lines = 0;
    bool parseError = false;
};

// A declarativeNetRequest redirect action.
struct DnrRedirect {
    QString ruleset;
    int ruleId = 0;
    QString target;  // url, regexSubstitution or transform summary
};

// The behavior signature of one extension version: what the manifest declares plus what the
// code can do. Two signatures are compared by the rules engine to produce findings.
struct Signature {
    int schema = 1;
    QString version;
    bool keyMatchesId = true;
    ManifestFacts manifest;

    QList<DnrHeaderMod> headerMods;
    QList<DnrRedirect> redirects;
    int allowAllRequestsRules = 0;
    int dnrRuleCount = 0;
    QStringList wasmFiles;
    QStringList analysisWarnings;  // "file: reason" for every place the analysis was incomplete

    QList<FileSummary> files;
    qint64 totalBytes = 0;
    QStringList contentScriptFiles;   // js files injected into web pages
    QStringList remoteScriptSources;  // <script src="https://..."> in extension pages

    QList<DomainRef> domains;
    QStringList chromeApis;
    QList<Sink> sinks;
    QList<TimerRef> timers;
    QList<ListenerRef> listeners;
    QStringList fingerprinting;
    QStringList fingerprintingFiles;
    QStringList securityHeaderLiterals;
    QStringList securityHeaderFiles;
    bool dynamicUrls = false;
    ObfuscationStats obfuscation;

    bool isEmpty() const { return manifest.raw.isEmpty() && files.isEmpty(); }
    QStringList domainHosts() const;
    bool hasSink(const QString& kind) const;
    QList<Sink> sinksOfKind(const QString& kind) const;
    QList<Sink> sinksInFile(const QString& file) const;

    QJsonObject toJson() const;
    static Signature fromJson(const QJsonObject& json);
};

// Reads every regular file under `dir`. With contentForAll false only analyzable files are read
// into memory; the rest keep name and size.
QList<SourceFile> loadSourcesFromDir(const QString& dir, bool contentForAll = true);

// Builds the signature. JavaScript is prettified before analysis so line numbers match the
// diff viewer. `expectedId` enables the key check when non-empty.
Signature buildSignature(const ManifestFacts& manifest, const QList<SourceFile>& files,
                         const QString& expectedId = QString());

}  // namespace extwatch
