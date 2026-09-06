#pragma once

#include <QByteArray>
#include <QList>

struct TSTree;

namespace extwatch {

// A parsed JavaScript source. The tree is shared by the prettifier and the analyzer so each
// file is parsed once.
class JsTree {
public:
    explicit JsTree(QByteArray utf8Source);
    ~JsTree();
    JsTree(const JsTree&) = delete;
    JsTree& operator=(const JsTree&) = delete;

    const QByteArray& source() const { return m_source; }
    TSTree* tree() const { return m_tree; }
    bool ok() const { return m_tree != nullptr; }

private:
    QByteArray m_source;
    TSTree* m_tree = nullptr;
};

// Node categories the formatter and analyzer care about, looked up by grammar symbol id
// (an integer) instead of comparing type-name strings for every node.
enum class NodeKind : quint8 {
    Other, String, TemplateString, Regex, Comment, HashBang, Jsx,
    StatementBlock, ClassBody, SwitchBody, Object, Array, Arguments, FormalParameters,
    ObjectPattern, ArrayPattern, NamedImports, ExportClause, Program, SwitchCase, SwitchDefault,
    Pair, UnaryExpression, TernaryExpression, FunctionLike,
    MemberExpression, CallExpression, NewExpression, AssignmentExpression, Identifier,
    PropertyIdentifier, Number,
};

NodeKind kindForSymbol(quint16 symbol);
bool isBinaryOperatorSymbol(quint16 symbol);      // "+", "=", "=>", "in", ...
bool isKeywordBeforeParenSymbol(quint16 symbol);  // "if", "return", "typeof", ...

// Maps byte offsets of the original source to line numbers of the prettified text.
struct LineMap {
    QList<quint32> offsets;  // ascending token start offsets
    QList<int> lines;        // 1-based prettified line for each offset

    int lineFor(quint32 offset) const;
};

}  // namespace extwatch
