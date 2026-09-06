#include "app/diffview.h"

#include <QFontDatabase>
#include <QHBoxLayout>
#include <QLabel>
#include <QPainter>
#include <QScrollBar>
#include <QTextBlock>
#include <QToolButton>
#include <QVBoxLayout>

#include "app/jshighlighter.h"

namespace extwatch {

namespace {

bool isDark(const QPalette& p) {
    return p.color(QPalette::Base).lightness() < 128;
}

QColor rowColor(LineKind kind, bool filler, const QPalette& p) {
    const bool dark = isDark(p);
    if (filler) {
        return dark ? QColor(255, 255, 255, 14) : QColor(0, 0, 0, 10);
    }
    switch (kind) {
        case LineKind::Added: return dark ? QColor(46, 160, 67, 70) : QColor(46, 160, 67, 55);
        case LineKind::Removed: return dark ? QColor(248, 81, 73, 70) : QColor(248, 81, 73, 50);
        default: return QColor(0, 0, 0, 0);
    }
}

class Gutter : public QWidget {
public:
    explicit Gutter(DiffPane* pane) : QWidget(pane), m_pane(pane) {}
    QSize sizeHint() const override { return QSize(m_pane->gutterWidth(), 0); }

protected:
    void paintEvent(QPaintEvent* event) override { m_pane->gutterPaint(event); }

private:
    DiffPane* m_pane;
};

}  // namespace

DiffPane::DiffPane(QWidget* parent) : QPlainTextEdit(parent) {
    setReadOnly(true);
    setLineWrapMode(QPlainTextEdit::NoWrap);
    setFrameShape(QFrame::NoFrame);
    QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    mono.setPointSizeF(mono.pointSizeF() - 0.5);
    setFont(mono);
    setTabStopDistance(fontMetrics().horizontalAdvance(u' ') * 2);
    m_gutter = new Gutter(this);
    connect(this, &QPlainTextEdit::blockCountChanged, this, [this](int) { updateGutterWidth(); });
    connect(this, &QPlainTextEdit::updateRequest, this, &DiffPane::updateGutter);
    updateGutterWidth();
}

int DiffPane::gutterWidth() const {
    int digits = 1;
    int max = qMax(1, static_cast<int>(m_lines.size()));
    while (max >= 10) {
        max /= 10;
        ++digits;
    }
    return 14 + fontMetrics().horizontalAdvance(u'9') * digits;
}

void DiffPane::updateGutterWidth() {
    setViewportMargins(gutterWidth(), 0, 0, 0);
}

void DiffPane::updateGutter(const QRect& rect, int dy) {
    if (dy) {
        m_gutter->scroll(0, dy);
    } else {
        m_gutter->update(0, rect.y(), m_gutter->width(), rect.height());
    }
}

void DiffPane::resizeEvent(QResizeEvent* event) {
    QPlainTextEdit::resizeEvent(event);
    const QRect cr = contentsRect();
    m_gutter->setGeometry(QRect(cr.left(), cr.top(), gutterWidth(), cr.height()));
}

void DiffPane::gutterPaint(QPaintEvent* event) {
    QPainter painter(m_gutter);
    const QPalette pal = palette();
    painter.fillRect(event->rect(), pal.color(QPalette::Window));
    QTextBlock block = firstVisibleBlock();
    int row = block.blockNumber();
    int top = static_cast<int>(blockBoundingGeometry(block).translated(contentOffset()).top());
    int bottom = top + static_cast<int>(blockBoundingRect(block).height());
    painter.setPen(pal.color(QPalette::PlaceholderText));
    while (block.isValid() && top <= event->rect().bottom()) {
        if (block.isVisible() && bottom >= event->rect().top() && row < m_lines.size()) {
            const PaneLine& l = m_lines.at(row);
            if (!l.filler && l.lineNo > 0) {
                painter.drawText(0, top, m_gutter->width() - 6, fontMetrics().height(), Qt::AlignRight,
                                 QString::number(l.lineNo));
            }
        }
        block = block.next();
        top = bottom;
        bottom = top + static_cast<int>(blockBoundingRect(block).height());
        ++row;
    }
}

void DiffPane::setLines(const QList<PaneLine>& lines, bool javascript) {
    m_lines = lines;
    m_highlightedRow = -1;
    QString text;
    qsizetype total = 0;
    for (const PaneLine& l : lines) {
        total += l.text.size() + 1;
    }
    text.reserve(total);
    for (qsizetype i = 0; i < lines.size(); ++i) {
        text += lines.at(i).text;
        if (i + 1 < lines.size()) {
            text += u'\n';
        }
    }
    delete m_highlighter;
    m_highlighter = nullptr;
    setPlainText(text);
    if (javascript && lines.size() <= 40000) {
        m_highlighter = new JsHighlighter(document(), isDark(palette()));
    }

    QList<QTextEdit::ExtraSelection> selections;
    int changed = 0;
    for (const PaneLine& l : lines) {
        if (l.kind != LineKind::Context || l.filler) {
            ++changed;
        }
    }
    if (changed <= 20000) {
        QTextBlock block = document()->firstBlock();
        for (qsizetype i = 0; i < lines.size() && block.isValid(); ++i, block = block.next()) {
            const PaneLine& l = lines.at(i);
            if (l.kind == LineKind::Context && !l.filler) {
                continue;
            }
            QTextEdit::ExtraSelection sel;
            sel.cursor = QTextCursor(block);
            sel.format.setBackground(rowColor(l.kind, l.filler, palette()));
            sel.format.setProperty(QTextFormat::FullWidthSelection, true);
            selections.append(sel);
        }
    }
    setExtraSelections(selections);
    updateGutterWidth();
    m_gutter->update();
}

void DiffPane::highlightRow(int row) {
    m_highlightedRow = row;
    QTextBlock block = document()->findBlockByNumber(row);
    if (!block.isValid()) {
        return;
    }
    QTextCursor cursor(block);
    setTextCursor(cursor);
    centerCursor();
}

DiffView::DiffView(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(4);

    auto* header = new QHBoxLayout();
    m_leftTitle = new QLabel(this);
    m_rightTitle = new QLabel(this);
    m_stats = new QLabel(this);
    m_stats->setStyleSheet(QStringLiteral("color: palette(mid);"));
    m_prev = new QToolButton(this);
    m_prev->setText(QStringLiteral("▲"));
    m_prev->setToolTip(QStringLiteral("Previous change"));
    m_next = new QToolButton(this);
    m_next->setText(QStringLiteral("▼"));
    m_next->setToolTip(QStringLiteral("Next change"));
    connect(m_prev, &QToolButton::clicked, this, &DiffView::previousHunk);
    connect(m_next, &QToolButton::clicked, this, &DiffView::nextHunk);
    header->addWidget(m_leftTitle, 1);
    header->addWidget(m_rightTitle, 1);
    header->addWidget(m_stats);
    header->addWidget(m_prev);
    header->addWidget(m_next);
    layout->addLayout(header);

    auto* panes = new QHBoxLayout();
    panes->setSpacing(1);
    m_left = new DiffPane(this);
    m_right = new DiffPane(this);
    panes->addWidget(m_left, 1);
    panes->addWidget(m_right, 1);
    layout->addLayout(panes, 1);

    auto sync = [this](QScrollBar* from, QScrollBar* to) {
        connect(from, &QScrollBar::valueChanged, this, [this, to](int v) {
            if (m_syncing) {
                return;
            }
            m_syncing = true;
            to->setValue(v);
            m_syncing = false;
        });
    };
    sync(m_left->verticalScrollBar(), m_right->verticalScrollBar());
    sync(m_right->verticalScrollBar(), m_left->verticalScrollBar());
    sync(m_left->horizontalScrollBar(), m_right->horizontalScrollBar());
    sync(m_right->horizontalScrollBar(), m_left->horizontalScrollBar());
}

void DiffView::clear(const QString& message) {
    m_left->setLines({}, false);
    m_right->setLines({{message, LineKind::Context, 0, false}}, false);
    m_leftTitle->clear();
    m_rightTitle->clear();
    m_stats->clear();
    m_hunkRows.clear();
    m_rowForNewLine.clear();
    m_currentHunk = -1;
    m_prev->setEnabled(false);
    m_next->setEnabled(false);
}

void DiffView::setTexts(const QString& oldText, const QString& newText, const QString& oldTitle,
                        const QString& newTitle, bool javascript) {
    const QStringList oldLines = splitLines(oldText);
    const QStringList newLines = splitLines(newText);
    const LineDiff diff = diffLines(oldLines, newLines);

    QList<PaneLine> left;
    QList<PaneLine> right;
    m_hunkRows.clear();
    m_rowForNewLine = QList<int>(newLines.size() + 1, -1);
    if (diff.truncated) {
        // Too big to align: show both sides unpaired.
        for (int i = 0; i < oldLines.size(); ++i) {
            left.append({oldLines.at(i), LineKind::Removed, i + 1, false});
        }
        for (int i = 0; i < newLines.size(); ++i) {
            right.append({newLines.at(i), LineKind::Added, i + 1, false});
            m_rowForNewLine[i + 1] = i;
        }
        m_stats->setText(QStringLiteral("file rewritten (too large to align)"));
    } else {
        qsizetype i = 0;
        const QList<DiffLine>& lines = diff.lines;
        while (i < lines.size()) {
            const DiffLine& l = lines.at(i);
            if (l.kind == LineKind::Context) {
                m_rowForNewLine[l.newLine] = static_cast<int>(left.size());
                left.append({l.text, LineKind::Context, l.oldLine, false});
                right.append({l.text, LineKind::Context, l.newLine, false});
                ++i;
                continue;
            }
            // A run of changes: removed lines first (canonical order), then added ones.
            m_hunkRows.append(static_cast<int>(left.size()));
            QList<const DiffLine*> removed;
            QList<const DiffLine*> added;
            while (i < lines.size() && lines.at(i).kind != LineKind::Context) {
                (lines.at(i).kind == LineKind::Removed ? removed : added).append(&lines.at(i));
                ++i;
            }
            const qsizetype rows = qMax(removed.size(), added.size());
            for (qsizetype r = 0; r < rows; ++r) {
                if (r < removed.size()) {
                    left.append({removed.at(r)->text, LineKind::Removed, removed.at(r)->oldLine, false});
                } else {
                    left.append({QString(), LineKind::Context, 0, true});
                }
                if (r < added.size()) {
                    m_rowForNewLine[added.at(r)->newLine] = static_cast<int>(right.size());
                    right.append({added.at(r)->text, LineKind::Added, added.at(r)->newLine, false});
                } else {
                    right.append({QString(), LineKind::Context, 0, true});
                }
            }
        }
        m_stats->setText(QStringLiteral("%1 changes · +%2 −%3").arg(m_hunkRows.size()).arg(diff.added).arg(diff.removed));
    }
    m_left->setLines(left, javascript);
    m_right->setLines(right, javascript);
    m_leftTitle->setText(oldTitle);
    m_rightTitle->setText(newTitle);
    m_currentHunk = -1;
    m_prev->setEnabled(!m_hunkRows.isEmpty());
    m_next->setEnabled(!m_hunkRows.isEmpty());
    if (!m_hunkRows.isEmpty()) {
        nextHunk();
    }
}

void DiffView::scrollToRow(int row) {
    m_left->highlightRow(row);
    m_right->highlightRow(row);
}

void DiffView::nextHunk() {
    if (m_hunkRows.isEmpty()) {
        return;
    }
    m_currentHunk = (m_currentHunk + 1) % m_hunkRows.size();
    scrollToRow(m_hunkRows.at(m_currentHunk));
    m_stats->setText(m_stats->text().section(QStringLiteral(" · change "), 0, 0) +
                     QStringLiteral(" · change %1/%2").arg(m_currentHunk + 1).arg(m_hunkRows.size()));
}

void DiffView::previousHunk() {
    if (m_hunkRows.isEmpty()) {
        return;
    }
    m_currentHunk = (m_currentHunk - 1 + static_cast<int>(m_hunkRows.size())) % m_hunkRows.size();
    scrollToRow(m_hunkRows.at(m_currentHunk));
    m_stats->setText(m_stats->text().section(QStringLiteral(" · change "), 0, 0) +
                     QStringLiteral(" · change %1/%2").arg(m_currentHunk + 1).arg(m_hunkRows.size()));
}

void DiffView::jumpToNewLine(int line) {
    if (line <= 0 || line >= m_rowForNewLine.size() || m_rowForNewLine.at(line) < 0) {
        return;
    }
    scrollToRow(m_rowForNewLine.at(line));
}

}  // namespace extwatch
