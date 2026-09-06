#!/usr/bin/env bash
# Builds an AppImage with linuxdeploy and its Qt plugin. Needs Qt 6 (qmake6 on PATH or QMAKE set),
# cmake, ninja, and network access to download linuxdeploy the first time.
set -euo pipefail
cd "$(dirname "$0")/../.."
VERSION="$(sed -n 's/.*VERSION \([0-9.]*\)$/\1/p' CMakeLists.txt | head -n1)"
ARCH="$(uname -m)"
TOOLS=build/tools; mkdir -p "$TOOLS" dist
fetch() { [ -x "$TOOLS/$1" ] || { curl -sSL -o "$TOOLS/$1" "$2"; chmod +x "$TOOLS/$1"; }; }
fetch linuxdeploy "https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-$ARCH.AppImage"
fetch linuxdeploy-plugin-qt "https://github.com/linuxdeploy/linuxdeploy-plugin-qt/releases/download/continuous/linuxdeploy-plugin-qt-$ARCH.AppImage"

cmake --preset release-linux >/dev/null
cmake --build --preset release-linux
rm -rf build/AppDir
DESTDIR="$PWD/build/AppDir" cmake --install build/release-linux >/dev/null

export QMAKE="${QMAKE:-$(command -v qmake6 || command -v qmake)}"
export EXTRA_QT_PLUGINS="sqldrivers;platforms;iconengines;imageformats"
export OUTPUT="dist/ExtWatch-$VERSION-$ARCH.AppImage"
export APPIMAGE_EXTRACT_AND_RUN=1
"$TOOLS/linuxdeploy" --appdir build/AppDir --plugin qt --output appimage \
  --desktop-file build/AppDir/usr/share/applications/extwatch.desktop \
  --icon-file build/AppDir/usr/share/icons/hicolor/256x256/apps/extwatch.png
echo "built $OUTPUT"
