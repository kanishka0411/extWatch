#include "core/textdiff.h"

#include <dtl/dtl.hpp>

#include <QHash>
#include <algorithm>
#include <vector>

namespace extwatch {

QStringList splitLines(const QString& text) {
    QStringList lines = text.split(u'\n');
    if (!lines.isEmpty() && lines.last().isEmpty()) {
        lines.removeLast();
    }
    for (QString& l : lines) {
        if (l.endsWith(u'\r')) {
            l.chop(1);
        }
    }
    return lines;
}

LineDiff diffLines(const QStringList& oldLines, const QStringList& newLines, int maxLines) {
    LineDiff result;
    if (oldLines.size() + newLines.size() > maxLines) {
        result.truncated = true;
        result.added = static_cast<int>(newLines.size());
        result.removed = static_cast<int>(oldLines.size());
        return result;
    }
    using Elem = quint64;
    auto hashLines = [](const QStringList& lines) {
        std::vector<Elem> out;
        out.reserve(static_cast<size_t>(lines.size()));
        for (const QString& l : lines) {
            out.push_back((static_cast<Elem>(qHash(l)) << 20) ^ static_cast<Elem>(l.size()));
        }
        return out;
    };
    const std::vector<Elem> a = hashLines(oldLines);
    const std::vector<Elem> b = hashLines(newLines);

    dtl::Diff<Elem, std::vector<Elem>> diff(a, b);
    if (a.size() + b.size() > 20000) {
        diff.onHuge();
    }
    diff.compose();
    const auto& ses = diff.getSes().getSequence();
    result.lines.reserve(static_cast<qsizetype>(ses.size()));
    int oldIdx = 0;
    int newIdx = 0;
    for (const auto& entry : ses) {
        DiffLine line;
        switch (entry.second.type) {
            case dtl::SES_ADD:
                line.kind = LineKind::Added;
                line.newLine = ++newIdx;
                line.text = newLines.at(newIdx - 1);
                result.added++;
                break;
            case dtl::SES_DELETE:
                line.kind = LineKind::Removed;
                line.oldLine = ++oldIdx;
                line.text = oldLines.at(oldIdx - 1);
                result.removed++;
                break;
            default: {
                // Hashes are only candidates for equality; a collision must not hide a change.
                const QString& oldText = oldLines.at(oldIdx);
                const QString& newText = newLines.at(newIdx);
                if (oldText != newText) {
                    DiffLine removed;
                    removed.kind = LineKind::Removed;
                    removed.oldLine = ++oldIdx;
                    removed.text = oldText;
                    result.lines.append(removed);
                    result.removed++;
                    line.kind = LineKind::Added;
                    line.newLine = ++newIdx;
                    line.text = newText;
                    result.added++;
                    break;
                }
                line.kind = LineKind::Context;
                line.oldLine = ++oldIdx;
                line.newLine = ++newIdx;
                line.text = newText;
                result.common++;
                break;
            }
        }
        result.lines.append(line);
    }
    // Canonical order inside each run of changes: removed lines first, then added lines.
    qsizetype i = 0;
    while (i < result.lines.size()) {
        if (result.lines.at(i).kind == LineKind::Context) {
            ++i;
            continue;
        }
        qsizetype j = i;
        while (j < result.lines.size() && result.lines.at(j).kind != LineKind::Context) {
            ++j;
        }
        std::stable_partition(result.lines.begin() + i, result.lines.begin() + j,
                              [](const DiffLine& l) { return l.kind == LineKind::Removed; });
        i = j;
    }
    return result;
}

QList<Hunk> hunksFromDiff(const LineDiff& diff, int context) {
    QList<Hunk> hunks;
    const QList<DiffLine>& lines = diff.lines;
    const qsizetype n = lines.size();
    qsizetype i = 0;
    while (i < n) {
        if (lines.at(i).kind == LineKind::Context) {
            ++i;
            continue;
        }
        // Start of a change run: back up `context` lines.
        qsizetype start = i;
        while (start > 0 && i - start < context && lines.at(start - 1).kind == LineKind::Context) {
            --start;
        }
        qsizetype end = i;
        qsizetype lastChange = i;
        while (end < n) {
            if (lines.at(end).kind != LineKind::Context) {
                lastChange = end;
                ++end;
                continue;
            }
            // context run: stop if it is longer than 2*context (next hunk) or reaches the end
            qsizetype run = end;
            while (run < n && lines.at(run).kind == LineKind::Context) {
                ++run;
            }
            if (run >= n || run - end > 2 * context) {
                end = qMin(run, lastChange + 1 + context);
                break;
            }
            end = run;
        }
        Hunk h;
        for (qsizetype k = start; k < end; ++k) {
            const DiffLine& l = lines.at(k);
            h.lines.append(l);
            if (l.kind != LineKind::Added) {
                if (h.oldStart == 0) {
                    h.oldStart = l.oldLine;
                }
                h.oldCount++;
            }
            if (l.kind != LineKind::Removed) {
                if (h.newStart == 0) {
                    h.newStart = l.newLine;
                }
                h.newCount++;
            }
        }
        if (h.oldStart == 0) {
            h.oldStart = h.lines.isEmpty() ? 0 : qMax(1, h.lines.first().oldLine);
        }
        if (h.newStart == 0) {
            h.newStart = h.lines.isEmpty() ? 0 : qMax(1, h.lines.first().newLine);
        }
        hunks.append(h);
        i = end;
    }
    return hunks;
}

QString unifiedDiff(const QString& oldName, const QString& newName, const QList<Hunk>& hunks) {
    QString out;
    out += QStringLiteral("--- %1\n+++ %2\n").arg(oldName, newName);
    for (const Hunk& h : hunks) {
        out += QStringLiteral("@@ -%1,%2 +%3,%4 @@\n")
                   .arg(h.oldStart)
                   .arg(h.oldCount)
                   .arg(h.newStart)
                   .arg(h.newCount);
        for (const DiffLine& l : h.lines) {
            const QChar prefix = l.kind == LineKind::Added ? u'+' : l.kind == LineKind::Removed ? u'-' : u' ';
            out += prefix;
            out += l.text;
            out += u'\n';
        }
    }
    return out;
}

}  // namespace extwatch
