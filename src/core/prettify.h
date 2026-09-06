#pragma once

#include <QByteArray>
#include <QString>

#include "core/jstree.h"

namespace extwatch {

// Deterministic structural formatter for JavaScript driven by the tree-sitter syntax tree:
// one statement per line, blocks indented, long literals broken up. Identical input always
// produces identical output, so diffing two formatted versions only shows real changes.
QString prettifyJavaScript(const QByteArray& utf8Source);

// Same, from an already parsed tree. When `map` is given it receives the byte-offset to line
// mapping so analysis of the original source can report prettified line numbers.
QString prettifyJavaScript(const JsTree& parsed, LineMap* map);

// Key-sorted, indented JSON. Returns the input unchanged when it does not parse.
QString prettifyJson(const QByteArray& utf8Source);

bool looksBinary(const QByteArray& data);

// Text to show for a file in the diff viewer, chosen by file extension.
QString displayText(const QString& path, const QByteArray& content);

// True for files the analysis and the diff viewer treat as JavaScript.
bool isJavaScriptPath(const QString& path);

}  // namespace extwatch
