#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QList>
#include <QString>
#include <QStringList>

#include "core/signature.h"

namespace extwatch {

enum class Severity { Info = 0, Low = 1, Medium = 2, High = 3 };

// Bump when a rule's meaning, severity or identity logic changes; stored findings from an older
// generation are recomputed from the cached signatures.
constexpr int kFindingsSchema = 1;

QString severityId(Severity s);
Severity severityFromId(const QString& id);

struct Finding {
    QString rule;
    Severity severity = Severity::Info;
    QString title;    // short, present tense: "Requests access to every website"
    QString detail;   // one or two sentences with the evidence
    QString file;     // where to look, may be empty
    int line = 0;

    QJsonObject toJson() const;
    static Finding fromJson(const QJsonObject& o);
};

struct RuleInfo {
    QString id;
    Severity severity;
    QString title;
    QString explanation;
};

// Every rule the engine can emit, for documentation and `extwatch rules`.
const QList<RuleInfo>& allRules();

// A finding for a rule that is raised outside signature comparison (store tracking).
Finding findingForRule(const QString& ruleId, const QString& detail);

// Findings that describe what `after` does that `before` did not. Pass an empty `before` for a
// baseline profile of a single version.
QList<Finding> compareSignatures(const Signature& before, const Signature& after);

Severity maxSeverity(const QList<Finding>& findings);

// A one-line summary of the most important findings, e.g.
// "+host access <all_urls>, polls cdn.example.invalid every 5 min, executes remote code"
QString findingsSummary(const QList<Finding>& findings, int maxItems = 3);

QJsonArray findingsToJson(const QList<Finding>& findings);
QList<Finding> findingsFromJson(const QJsonArray& array);

// Hosts that are common infrastructure and do not by themselves indicate exfiltration.
bool isAllowlistedHost(const QString& host, const ManifestFacts& manifest);

}  // namespace extwatch
