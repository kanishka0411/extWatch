#pragma once

#include <QList>
#include <QString>
#include <QStringList>

namespace extwatch {

enum class LineKind { Context, Added, Removed };

struct DiffLine {
    LineKind kind = LineKind::Context;
    int oldLine = 0;  // 1-based, 0 when the line does not exist on that side
    int newLine = 0;
    QString text;
};

struct Hunk {
    int oldStart = 0;
    int oldCount = 0;
    int newStart = 0;
    int newCount = 0;
    QList<DiffLine> lines;
};

struct LineDiff {
    QList<DiffLine> lines;  // the full edit script, context lines included
    int added = 0;
    int removed = 0;
    int common = 0;
    bool truncated = false;  // inputs exceeded the work cap; lines is empty
};

QStringList splitLines(const QString& text);

// Myers diff over lines (dtl). Inputs larger than maxLines lines in total are not diffed.
LineDiff diffLines(const QStringList& oldLines, const QStringList& newLines, int maxLines = 300000);

QList<Hunk> hunksFromDiff(const LineDiff& diff, int context = 3);

// Unified diff text for the given hunks.
QString unifiedDiff(const QString& oldName, const QString& newName, const QList<Hunk>& hunks);

}  // namespace extwatch
