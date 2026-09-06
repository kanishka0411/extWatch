#include "core/jstree.h"

#include <tree_sitter/api.h>

#include <algorithm>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

extern "C" const TSLanguage* tree_sitter_javascript(void);

namespace extwatch {

JsTree::JsTree(QByteArray utf8Source) : m_source(std::move(utf8Source)) {
    if (m_source.startsWith("\xEF\xBB\xBF")) {
        m_source.remove(0, 3);
    }
    TSParser* parser = ts_parser_new();
    ts_parser_set_language(parser, tree_sitter_javascript());
    m_tree = ts_parser_parse_string(parser, nullptr, m_source.constData(),
                                    static_cast<uint32_t>(m_source.size()));
    ts_parser_delete(parser);
}

JsTree::~JsTree() {
    if (m_tree) {
        ts_tree_delete(m_tree);
    }
}

namespace {

struct SymbolTables {
    std::vector<NodeKind> kind;
    std::vector<bool> binaryOp;
    std::vector<bool> keywordBeforeParen;

    SymbolTables() {
        const TSLanguage* lang = tree_sitter_javascript();
        const uint32_t count = ts_language_symbol_count(lang);
        kind.assign(count, NodeKind::Other);
        binaryOp.assign(count, false);
        keywordBeforeParen.assign(count, false);
        static const std::unordered_set<std::string_view> ops = {
            "=",  "==", "===", "!=", "!==", "+",  "-",  "*",   "/",   "%",   "**",  "<",   ">",
            "<=", ">=", "&&",  "||", "?\?",  "+=", "-=", "*=",  "/=",  "%=",  "**=", "<<=", ">>=",
            ">>>=", "&=", "|=", "^=", "&&=", "||=", "?\?=", "<<", ">>", ">>>", "&",  "|",   "^",
            "=>", "?",  "in",  "of", "instanceof",
        };
        static const std::unordered_set<std::string_view> kw = {
            "if",   "for",   "while", "switch", "catch", "with",  "return", "typeof", "await",
            "yield", "throw", "delete", "void",  "new",   "case",  "in",     "of",     "else",
            "do",   "async", "function", "instanceof", "export", "default",
        };
        static const std::unordered_map<std::string_view, NodeKind> named = {
            {"string", NodeKind::String}, {"template_string", NodeKind::TemplateString},
            {"regex", NodeKind::Regex}, {"comment", NodeKind::Comment},
            {"hash_bang_line", NodeKind::HashBang}, {"statement_block", NodeKind::StatementBlock},
            {"class_body", NodeKind::ClassBody}, {"switch_body", NodeKind::SwitchBody},
            {"object", NodeKind::Object}, {"array", NodeKind::Array}, {"arguments", NodeKind::Arguments},
            {"formal_parameters", NodeKind::FormalParameters}, {"object_pattern", NodeKind::ObjectPattern},
            {"array_pattern", NodeKind::ArrayPattern}, {"named_imports", NodeKind::NamedImports},
            {"export_clause", NodeKind::ExportClause}, {"program", NodeKind::Program},
            {"switch_case", NodeKind::SwitchCase}, {"switch_default", NodeKind::SwitchDefault},
            {"pair", NodeKind::Pair}, {"unary_expression", NodeKind::UnaryExpression},
            {"ternary_expression", NodeKind::TernaryExpression},
            {"function_expression", NodeKind::FunctionLike}, {"arrow_function", NodeKind::FunctionLike},
            {"function", NodeKind::FunctionLike}, {"method_definition", NodeKind::FunctionLike},
            {"class", NodeKind::FunctionLike}, {"generator_function", NodeKind::FunctionLike},
            {"member_expression", NodeKind::MemberExpression}, {"call_expression", NodeKind::CallExpression},
            {"new_expression", NodeKind::NewExpression}, {"assignment_expression", NodeKind::AssignmentExpression},
            {"identifier", NodeKind::Identifier}, {"property_identifier", NodeKind::PropertyIdentifier},
            {"shorthand_property_identifier", NodeKind::Identifier}, {"number", NodeKind::Number},
        };
        for (uint32_t i = 0; i < count; ++i) {
            const char* name = ts_language_symbol_name(lang, static_cast<TSSymbol>(i));
            if (!name) {
                continue;
            }
            const std::string_view sv(name);
            const TSSymbolType type = ts_language_symbol_type(lang, static_cast<TSSymbol>(i));
            if (type == TSSymbolTypeRegular) {
                if (auto it = named.find(sv); it != named.end()) {
                    kind[i] = it->second;
                } else if (sv.size() >= 3 && sv.compare(0, 3, "jsx") == 0) {
                    kind[i] = NodeKind::Jsx;
                }
            } else if (type == TSSymbolTypeAnonymous) {
                binaryOp[i] = ops.count(sv) > 0;
                keywordBeforeParen[i] = kw.count(sv) > 0;
            }
        }
    }
};

const SymbolTables& tables() {
    static const SymbolTables t;
    return t;
}

}  // namespace

NodeKind kindForSymbol(quint16 symbol) {
    const SymbolTables& t = tables();
    return symbol < t.kind.size() ? t.kind[symbol] : NodeKind::Other;
}

bool isBinaryOperatorSymbol(quint16 symbol) {
    const SymbolTables& t = tables();
    return symbol < t.binaryOp.size() && t.binaryOp[symbol];
}

bool isKeywordBeforeParenSymbol(quint16 symbol) {
    const SymbolTables& t = tables();
    return symbol < t.keywordBeforeParen.size() && t.keywordBeforeParen[symbol];
}

int LineMap::lineFor(quint32 offset) const {
    if (offsets.isEmpty()) {
        return 1;
    }
    auto it = std::upper_bound(offsets.begin(), offsets.end(), offset);
    if (it == offsets.begin()) {
        return lines.first();
    }
    return lines.at(static_cast<qsizetype>(it - offsets.begin()) - 1);
}

}  // namespace extwatch
