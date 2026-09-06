#include "app/jshighlighter.h"

namespace extwatch {

namespace {
enum BlockState { Normal = 0, InBlockComment = 1, InTemplate = 2 };
}

JsHighlighter::JsHighlighter(QTextDocument* parent, bool dark) : QSyntaxHighlighter(parent) {
    QTextCharFormat keyword;
    keyword.setForeground(dark ? QColor(0xc6, 0x8c, 0xff) : QColor(0x7a, 0x2e, 0xb8));
    keyword.setFontWeight(QFont::DemiBold);
    QTextCharFormat string;
    string.setForeground(dark ? QColor(0x9e, 0xd6, 0x7a) : QColor(0x0b, 0x6b, 0x2c));
    QTextCharFormat number;
    number.setForeground(dark ? QColor(0xf5, 0xb8, 0x5a) : QColor(0xa8, 0x5a, 0x00));
    QTextCharFormat api;
    api.setForeground(dark ? QColor(0x6c, 0xb6, 0xff) : QColor(0x0b, 0x57, 0xd0));
    api.setFontWeight(QFont::DemiBold);
    QTextCharFormat danger;
    danger.setForeground(dark ? QColor(0xff, 0x7b, 0x7b) : QColor(0xc0, 0x1f, 0x1f));
    danger.setFontWeight(QFont::Bold);
    m_commentFormat.setForeground(dark ? QColor(0x8a, 0x93, 0xa6) : QColor(0x6a, 0x73, 0x7d));
    m_commentFormat.setFontItalic(true);
    m_templateFormat = string;

    m_rules.append({QRegularExpression(QStringLiteral(
                        "\\b(?:async|await|break|case|catch|class|const|continue|debugger|default|delete|do|else|export|extends|"
                        "finally|for|function|if|import|in|instanceof|let|new|of|return|static|super|switch|this|throw|try|typeof|"
                        "var|void|while|with|yield|true|false|null|undefined)\\b")),
                    keyword});
    m_rules.append({QRegularExpression(QStringLiteral("\\b(?:chrome|browser)\\.[A-Za-z_.]+")), api});
    m_rules.append({QRegularExpression(QStringLiteral("\\b(?:eval|Function|importScripts|setAttribute|fetch|XMLHttpRequest|WebSocket|atob|innerHTML)\\b")), danger});
    m_rules.append({QRegularExpression(QStringLiteral("\\b(?:0x[0-9A-Fa-f]+|\\d+(?:\\.\\d+)?(?:e[+-]?\\d+)?)\\b")), number});
    m_rules.append({QRegularExpression(QStringLiteral("\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*'")), string});
    m_rules.append({QRegularExpression(QStringLiteral("//[^\n]*")), m_commentFormat});
    m_commentStart = QRegularExpression(QStringLiteral("/\\*"));
    m_commentEnd = QRegularExpression(QStringLiteral("\\*/"));
}

void JsHighlighter::highlightBlock(const QString& text) {
    if (text.size() > 4000) {
        return;  // a single enormous line: skip, it would only slow the view down
    }
    for (const Rule& rule : m_rules) {
        QRegularExpressionMatchIterator it = rule.pattern.globalMatch(text);
        while (it.hasNext()) {
            const QRegularExpressionMatch m = it.next();
            setFormat(static_cast<int>(m.capturedStart()), static_cast<int>(m.capturedLength()), rule.format);
        }
    }
    // Multi-line constructs: block comments and template strings.
    setCurrentBlockState(Normal);
    int start = 0;
    if (previousBlockState() == InBlockComment) {
        start = 0;
    } else {
        start = static_cast<int>(text.indexOf(m_commentStart));
    }
    while (start >= 0) {
        const QRegularExpressionMatch end = m_commentEnd.match(text, start + (previousBlockState() == InBlockComment && start == 0 ? 0 : 2));
        int length;
        if (!end.hasMatch()) {
            setCurrentBlockState(InBlockComment);
            length = static_cast<int>(text.size()) - start;
        } else {
            length = static_cast<int>(end.capturedEnd()) - start;
        }
        setFormat(start, length, m_commentFormat);
        start = static_cast<int>(text.indexOf(m_commentStart, start + length));
    }
    if (currentBlockState() == Normal) {
        int tstart = previousBlockState() == InTemplate ? 0 : static_cast<int>(text.indexOf(u'`'));
        while (tstart >= 0) {
            const int from = (previousBlockState() == InTemplate && tstart == 0) ? 0 : tstart + 1;
            const int tend = static_cast<int>(text.indexOf(u'`', from));
            if (tend < 0) {
                setFormat(tstart, static_cast<int>(text.size()) - tstart, m_templateFormat);
                setCurrentBlockState(InTemplate);
                break;
            }
            setFormat(tstart, tend - tstart + 1, m_templateFormat);
            tstart = static_cast<int>(text.indexOf(u'`', tend + 1));
        }
    }
}

}  // namespace extwatch
