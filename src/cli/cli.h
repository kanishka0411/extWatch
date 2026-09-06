#pragma once

#include <QStringList>

namespace extwatch::cli {

// True when the arguments select a command-line mode rather than the tray app.
bool wantsCli(const QStringList& args);

// Runs the CLI and returns the process exit code.
int run(const QStringList& args);

}  // namespace extwatch::cli
