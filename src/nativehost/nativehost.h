#pragma once

#include <QStringList>

namespace extwatch {

// Native messaging host mode: relays framed JSON between the browser (stdin/stdout) and the
// ExtWatch app (local socket). Returns the process exit code when the browser closes the pipe.
int runNativeHost(const QStringList& args);

}  // namespace extwatch
