#pragma once

#include <QRegularExpression>
#include <QSyntaxHighlighter>
#include <QTextCharFormat>
#include <QVector>

namespace extwatch {

// Lightweight JavaScript/JSON highlighter for the diff panes (keywords, strings, numbers,
// comments, chrome.* API calls). Colors adapt to a light or dark palette.
class JsHighlighter : public QSyntaxHighlighter {
    Q_OBJECT
public:
    explicit JsHighlighter(QTextDocument* parent, bool darkPalette);

protected:
    void highlightBlock(const QString& text) override;

private:
    struct Rule {
        QRegularExpression pattern;
        QTextCharFormat format;
    };
    QVector<Rule> m_rules;
    QTextCharFormat m_commentFormat;
    QTextCharFormat m_templateFormat;
    QRegularExpression m_commentStart;
    QRegularExpression m_commentEnd;
};

}  // namespace extwatch
