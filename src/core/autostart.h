#pragma once

#include <QString>

namespace extwatch {

// Per-user login item for the tray app (LaunchAgent, XDG autostart entry, or the Run registry key).
bool isAutostartEnabled();
bool setAutostartEnabled(bool enabled, QString* error = nullptr);

}  // namespace extwatch
