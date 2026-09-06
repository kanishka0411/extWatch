#include "core/prettify.h"

#include <tree_sitter/api.h>

#include <QJsonDocument>
#include <cstring>
#include <string_view>

namespace extwatch {

namespace {

using sv = std::string_view;

bool isWordStart(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '$' || c == '"' ||
           c == '\'' || c == '`' || c == '#' || c == '@' || static_cast<unsigned char>(c) >= 0x80;
}

NodeKind kindOf(TSNode n) {
    return kindForSymbol(ts_node_symbol(n));
}

bool isContainer(NodeKind k) {
    switch (k) {
        case NodeKind::StatementBlock: case NodeKind::ClassBody: case NodeKind::SwitchBody:
        case NodeKind::Object: case NodeKind::Array: case NodeKind::Arguments:
        case NodeKind::FormalParameters: case NodeKind::ObjectPattern: case NodeKind::ArrayPattern:
        case NodeKind::NamedImports: case NodeKind::ExportClause:
            return true;
        default:
            return false;
    }
}

bool isStatementList(NodeKind k) {
    switch (k) {
        case NodeKind::Program: case NodeKind::StatementBlock: case NodeKind::ClassBody:
        case NodeKind::SwitchBody: case NodeKind::SwitchCase: case NodeKind::SwitchDefault:
            return true;
        default:
            return false;
    }
}

bool isVerbatimLeaf(NodeKind k) {
    switch (k) {
        case NodeKind::String: case NodeKind::TemplateString: case NodeKind::Regex:
        case NodeKind::Jsx: case NodeKind::Comment: case NodeKind::HashBang:
            return true;
        default:
            return false;
    }
}

struct Printer {
    const QByteArray& src;
    LineMap* map;
    QByteArray out;
    int indent = 0;
    int line = 1;
    bool atLineStart = true;
    sv prev;
    quint16 prevSym = 0;
    bool prevIsWord = false;
    bool prevWasUnary = false;
    bool prevWasLineComment = false;
    quint32 lastMapped = 0;
    bool anyMapped = false;

    sv text(TSNode n) const {
        const uint32_t a = ts_node_start_byte(n);
        const uint32_t b = ts_node_end_byte(n);
        return sv(src.constData() + a, b - a);
    }

    void newline() {
        if (!atLineStart) {
            out += '\n';
            ++line;
            atLineStart = true;
        }
    }

    bool wantSpaceBefore(sv cur, quint16 curSym, bool curIsWord, NodeKind parentKind) const {
        if (atLineStart || prev.empty() || prevWasLineComment) {
            return false;
        }
        if (cur.size() <= 2) {
            if (cur == ";" || cur == "," || cur == ")" || cur == "]" || cur == "." || cur == "?.") {
                return false;
            }
            if (cur == ":") {
                return parentKind == NodeKind::TernaryExpression;
            }
            if (cur == "(") {
                if (isKeywordBeforeParenSymbol(prevSym)) {
                    return true;
                }
                if (prevIsWord || prev == ")" || prev == "]" || prev == "}") {
                    return false;
                }
                return prev != "(" && prev != "[" && prev != "!" && prev != "~";
            }
            if (cur == "[") {
                if (isKeywordBeforeParenSymbol(prevSym)) {
                    return true;
                }
                if (prevIsWord || prev == ")" || prev == "]") {
                    return false;
                }
                return prev != "(" && prev != "[" && prev != "!" && prev != "~";
            }
            if (cur == "{") {
                return prev != "(" && prev != "[" && prev != "!" && prev != "~";
            }
            if (cur == "++" || cur == "--") {
                return !(prevIsWord || prev == ")" || prev == "]");
            }
        }
        if (prev.size() <= 3 &&
            (prev == "(" || prev == "[" || prev == "." || prev == "?." || prev == "!" || prev == "~" ||
             prev == "..." || prev == "++" || prev == "--")) {
            return false;
        }
        if (prevWasUnary) {
            return false;
        }
        if (prevIsWord && curIsWord) {
            return true;
        }
        if (isBinaryOperatorSymbol(prevSym) || isBinaryOperatorSymbol(curSym)) {
            return true;
        }
        if (prev.size() == 1 && (prev == "," || prev == ";" || prev == ":")) {
            return true;
        }
        if ((prev == ")" || prev == "]") && (curIsWord || cur == "{")) {
            return true;
        }
        if (prev == "}" && (curIsWord || cur == "{")) {
            return true;
        }
        if (prev == "{" && curIsWord) {
            return true;
        }
        return false;
    }

    void put(sv tok, quint16 sym, bool isWord, NodeKind parentKind, bool unary, quint32 offset, bool mapped) {
        if (tok.empty()) {
            return;
        }
        if (atLineStart) {
            out.append(indent * 2, ' ');
            atLineStart = false;
        } else if (wantSpaceBefore(tok, sym, isWord, parentKind)) {
            out += ' ';
        }
        if (map && mapped && (!anyMapped || offset > lastMapped)) {
            map->offsets.append(offset);
            map->lines.append(line);
            lastMapped = offset;
            anyMapped = true;
        }
        out.append(tok.data(), static_cast<qsizetype>(tok.size()));
        if (tok.size() > 1) {
            for (const char c : tok) {
                if (c == '\n') {
                    ++line;
                }
            }
        }
        prev = tok;
        prevSym = sym;
        prevIsWord = isWord;
        prevWasUnary = unary;
        prevWasLineComment = false;
    }

    bool hasComplexChild(TSNode n, uint32_t sizeLimit) const {
        int scanned = 0;
        bool found = false;
        TSTreeCursor cursor = ts_tree_cursor_new(n);
        if (ts_tree_cursor_goto_first_child(&cursor)) {
            do {
                TSNode c = ts_tree_cursor_current_node(&cursor);
                if (!ts_node_is_named(c)) {
                    continue;
                }
                if (++scanned > 64) {
                    break;
                }
                if (kindOf(c) == NodeKind::Pair) {
                    TSNode v = ts_node_child_by_field_name(c, "value", 5);
                    if (!ts_node_is_null(v)) {
                        c = v;
                    }
                }
                const NodeKind ck = kindOf(c);
                if (ck == NodeKind::Object || ck == NodeKind::Array || ck == NodeKind::FunctionLike) {
                    if (ts_node_end_byte(c) - ts_node_start_byte(c) > sizeLimit) {
                        found = true;
                        break;
                    }
                }
            } while (ts_tree_cursor_goto_next_sibling(&cursor));
        }
        ts_tree_cursor_delete(&cursor);
        return found;
    }

    bool shouldBreak(TSNode n, NodeKind k) const {
        const uint32_t named = ts_node_named_child_count(n);
        if (named == 0) {
            return false;
        }
        const uint32_t len = ts_node_end_byte(n) - ts_node_start_byte(n);
        switch (k) {
            case NodeKind::StatementBlock: case NodeKind::ClassBody: case NodeKind::SwitchBody:
                return true;
            case NodeKind::Object:
                return len > 60 || named > 4 || hasComplexChild(n, 20);
            case NodeKind::Array:
                return len > 80 || hasComplexChild(n, 40);
            case NodeKind::Arguments:
                return named > 1 && len > 100;
            case NodeKind::FormalParameters: case NodeKind::ObjectPattern: case NodeKind::ArrayPattern:
            case NodeKind::NamedImports: case NodeKind::ExportClause:
                return len > 100;
            default:
                return false;
        }
    }

    void visitContainer(TSNode n, NodeKind k, NodeKind parentKind, int depth) {
        const uint32_t count = ts_node_child_count(n);
        const bool breakIt = shouldBreak(n, k);
        const bool isObject = k == NodeKind::Object;
        const bool statements = isStatementList(k);
        const bool nonEmptyObject = isObject && ts_node_named_child_count(n) > 0;
        TSTreeCursor cursor = ts_tree_cursor_new(n);
        if (ts_tree_cursor_goto_first_child(&cursor)) {
            uint32_t i = 0;
            do {
                TSNode c = ts_tree_cursor_current_node(&cursor);
                const bool named = ts_node_is_named(c);
                const sv tok = named ? sv() : text(c);
                const quint16 sym = ts_node_symbol(c);
                if (i == 0 && !named) {  // opening bracket
                    put(tok, sym, false, parentKind, false, ts_node_start_byte(c), true);
                    if (breakIt) {
                        indent++;
                        newline();
                    }
                } else if (i == count - 1 && !named && (tok == "}" || tok == "]" || tok == ")")) {
                    if (breakIt) {
                        indent--;
                        newline();
                    } else if (nonEmptyObject) {
                        out += ' ';
                    }
                    put(tok, sym, false, parentKind, false, 0, false);
                } else if (!named && tok == ",") {
                    put(tok, sym, false, k, false, 0, false);
                    if (breakIt) {
                        newline();
                    }
                } else if (!named && tok == ";") {
                    put(tok, sym, false, k, false, 0, false);
                    if (statements) {
                        newline();
                    }
                } else {
                    if (isObject && !breakIt && i == 1) {
                        out += ' ';
                        atLineStart = false;
                    }
                    visit(c, k, depth + 1);
                    if (statements && named) {
                        newline();
                    }
                }
                ++i;
            } while (ts_tree_cursor_goto_next_sibling(&cursor));
        }
        ts_tree_cursor_delete(&cursor);
    }

    void visit(TSNode n, NodeKind parentKind, int depth) {
        const NodeKind k = kindOf(n);
        const uint32_t count = ts_node_child_count(n);
        const quint16 sym = ts_node_symbol(n);

        if (depth > 400) {
            put(text(n), sym, true, parentKind, false, ts_node_start_byte(n), true);
            return;
        }
        if (count == 0 || isVerbatimLeaf(k)) {
            const sv tok = text(n);
            const quint32 offset = ts_node_start_byte(n);
            if (k == NodeKind::Comment) {
                const bool lineComment = tok.size() >= 2 && tok[0] == '/' && tok[1] == '/';
                put(tok, sym, true, parentKind, false, offset, true);
                if (lineComment) {
                    newline();
                    prevWasLineComment = true;
                }
                return;
            }
            if (k == NodeKind::HashBang) {
                put(tok, sym, true, parentKind, false, offset, true);
                newline();
                return;
            }
            const bool word = !tok.empty() && (isWordStart(tok[0]) || ts_node_is_named(n));
            const bool unary = parentKind == NodeKind::UnaryExpression && !word;
            put(tok, sym, word, parentKind, unary, offset, true);
            return;
        }
        if (isContainer(k)) {
            visitContainer(n, k, parentKind, depth);
            return;
        }
        if (k == NodeKind::Program) {
            TSTreeCursor cursor = ts_tree_cursor_new(n);
            if (ts_tree_cursor_goto_first_child(&cursor)) {
                do {
                    TSNode c = ts_tree_cursor_current_node(&cursor);
                    visit(c, k, depth + 1);
                    if (ts_node_is_named(c)) {
                        newline();
                    }
                } while (ts_tree_cursor_goto_next_sibling(&cursor));
            }
            ts_tree_cursor_delete(&cursor);
            return;
        }
        if (k == NodeKind::SwitchCase || k == NodeKind::SwitchDefault) {
            bool inBody = false;
            TSTreeCursor cursor = ts_tree_cursor_new(n);
            if (ts_tree_cursor_goto_first_child(&cursor)) {
                do {
                    TSNode c = ts_tree_cursor_current_node(&cursor);
                    if (!inBody) {
                        visit(c, k, depth + 1);
                        if (!ts_node_is_named(c) && text(c) == ":") {
                            inBody = true;
                            indent++;
                            newline();
                        }
                        continue;
                    }
                    visit(c, k, depth + 1);
                    newline();
                } while (ts_tree_cursor_goto_next_sibling(&cursor));
            }
            ts_tree_cursor_delete(&cursor);
            if (inBody) {
                indent--;
            }
            return;
        }
        TSTreeCursor cursor = ts_tree_cursor_new(n);
        if (ts_tree_cursor_goto_first_child(&cursor)) {
            do {
                visit(ts_tree_cursor_current_node(&cursor), k, depth + 1);
            } while (ts_tree_cursor_goto_next_sibling(&cursor));
        }
        ts_tree_cursor_delete(&cursor);
    }
};

}  // namespace

bool isJavaScriptPath(const QString& path) {
    const QString lower = path.toLower();
    return lower.endsWith(QStringLiteral(".js")) || lower.endsWith(QStringLiteral(".mjs")) ||
           lower.endsWith(QStringLiteral(".cjs")) || lower.endsWith(QStringLiteral(".jsx"));
}

QString prettifyJavaScript(const JsTree& parsed, LineMap* map) {
    if (!parsed.ok()) {
        return QString::fromUtf8(parsed.source());
    }
    Printer p{parsed.source(), map, {}, 0, 1, true, {}, 0, false, false, false, 0, false};
    p.out.reserve(parsed.source().size() + parsed.source().size() / 4);
    p.visit(ts_tree_root_node(parsed.tree()), NodeKind::Other, 0);
    p.newline();
    return QString::fromUtf8(p.out);
}

QString prettifyJavaScript(const QByteArray& input) {
    const JsTree parsed(input);
    return prettifyJavaScript(parsed, nullptr);
}

QString prettifyJson(const QByteArray& utf8Source) {
    QByteArray data = utf8Source;
    if (data.startsWith("\xEF\xBB\xBF")) {
        data.remove(0, 3);
    }
    const QJsonDocument doc = QJsonDocument::fromJson(data);
    if (doc.isNull()) {
        return QString::fromUtf8(data);
    }
    return QString::fromUtf8(doc.toJson(QJsonDocument::Indented));
}

bool looksBinary(const QByteArray& data) {
    const int n = static_cast<int>(qMin<qsizetype>(data.size(), 8192));
    for (int i = 0; i < n; ++i) {
        if (data.at(i) == '\0') {
            return true;
        }
    }
    return false;
}

QString displayText(const QString& path, const QByteArray& content) {
    if (isJavaScriptPath(path)) {
        return prettifyJavaScript(content);
    }
    const QString lower = path.toLower();
    if (lower.endsWith(QStringLiteral(".json"))) {
        return prettifyJson(content);
    }
    if (looksBinary(content)) {
        return QStringLiteral("[binary file, %1 bytes]\n").arg(content.size());
    }
    return QString::fromUtf8(content);
}

}  // namespace extwatch
