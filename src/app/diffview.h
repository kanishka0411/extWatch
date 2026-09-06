#pragma once

#include <QList>
#include <QPlainTextEdit>
#include <QString>
#include <QWidget>

#include "core/textdiff.h"

class QLabel;
class QToolButton;

namespace extwatch {

class JsHighlighter;

struct PaneLine {
    QString text;
    LineKind kind = LineKind::Context;
    int lineNo = 0;       // 0 for filler rows
    bool filler = false;  // padding so both panes stay aligned
};

// One side of the side-by-side view: read-only editor with a line-number gutter and colored
// backgrounds for changed and filler rows.
class DiffPane : public QPlainTextEdit {
    Q_OBJECT
public:
    explicit DiffPane(QWidget* parent = nullptr);
    void setLines(const QList<PaneLine>& lines, bool javascript);
    void gutterPaint(QPaintEvent* event);
    int gutterWidth() const;
    void highlightRow(int row);

protected:
    void resizeEvent(QResizeEvent* event) override;

private:
    void updateGutterWidth();
    void updateGutter(const QRect& rect, int dy);

    QWidget* m_gutter = nullptr;
    QList<PaneLine> m_lines;
    JsHighlighter* m_highlighter = nullptr;
    int m_highlightedRow = -1;
};

// Side-by-side diff of two texts with synchronized scrolling and hunk navigation.
class DiffView : public QWidget {
    Q_OBJECT
public:
    explicit DiffView(QWidget* parent = nullptr);

    void setTexts(const QString& oldText, const QString& newText, const QString& oldTitle,
                  const QString& newTitle, bool javascript);
    void clear(const QString& message = QString());
    void jumpToNewLine(int line);
    int hunkCount() const { return static_cast<int>(m_hunkRows.size()); }

public slots:
    void nextHunk();
    void previousHunk();

private:
    void scrollToRow(int row);

    DiffPane* m_left = nullptr;
    DiffPane* m_right = nullptr;
    QLabel* m_leftTitle = nullptr;
    QLabel* m_rightTitle = nullptr;
    QLabel* m_stats = nullptr;
    QToolButton* m_prev = nullptr;
    QToolButton* m_next = nullptr;
    QList<int> m_hunkRows;
    QList<int> m_rowForNewLine;  // new line number -> row
    int m_currentHunk = -1;
    bool m_syncing = false;
};

}  // namespace extwatch
