#!/usr/bin/env bash
# Builds an AppImage with linuxdeploy and its Qt plugin. Needs Qt 6 (qmake6 on PATH or QMAKE set),
# cmake, ninja, and network access to download linuxdeploy the first time.
set -euo pipefail
cd "$(dirname "$0")/../.."
VERSION="$(sed -n 's/.*VERSION \([0-9.]*\)$/\1/p' CMakeLists.txt | head -n1)"
ARCH="$(uname -m)"
TOOLS=build/tools; mkdir -p "$TOOLS" dist
# Pinned tool releases with checksums: a release build must not execute whatever "continuous" is today.
LINUXDEPLOY_TAG=1-alpha-20251107-1
PLUGIN_QT_TAG=1-alpha-20250213-1
case "$ARCH" in
  x86_64)  LINUXDEPLOY_SHA=c20cd71e3a4e3b80c3483cef793cda3f4e990aca14014d23c544ca3ce1270b4d; PLUGIN_QT_SHA=15106be885c1c48a021198e7e1e9a48ce9d02a86dd0a1848f00bdbf3c1c92724 ;;
  aarch64) LINUXDEPLOY_SHA=620095110d693282b8ebeb244a95b5e911cf8f65f76c88b4b47d16ae6346fcff; PLUGIN_QT_SHA=bf1c24aff6d749b5cf423afad6f15abd4440f81dec1aab95706b25f6667cdcf1 ;;
  *) echo "no pinned linuxdeploy checksum for $ARCH" >&2; exit 1 ;;
esac
fetch() {  # fetch <name> <url> <sha256>
  if [ ! -x "$TOOLS/$1" ]; then
    curl -sSL -o "$TOOLS/$1.download" "$2"
    echo "$3  $TOOLS/$1.download" | sha256sum -c - >/dev/null || { echo "checksum mismatch for $1" >&2; rm -f "$TOOLS/$1.download"; exit 1; }
    mv "$TOOLS/$1.download" "$TOOLS/$1"; chmod +x "$TOOLS/$1"
  fi
}
fetch linuxdeploy "https://github.com/linuxdeploy/linuxdeploy/releases/download/$LINUXDEPLOY_TAG/linuxdeploy-$ARCH.AppImage" "$LINUXDEPLOY_SHA"
fetch linuxdeploy-plugin-qt "https://github.com/linuxdeploy/linuxdeploy-plugin-qt/releases/download/$PLUGIN_QT_TAG/linuxdeploy-plugin-qt-$ARCH.AppImage" "$PLUGIN_QT_SHA"

cmake --preset release-linux >/dev/null
cmake --build --preset release-linux
rm -rf build/AppDir
DESTDIR="$PWD/build/AppDir" cmake --install build/release-linux >/dev/null

export QMAKE="${QMAKE:-$(command -v qmake6 || command -v qmake)}"
export EXTRA_QT_PLUGINS="sqldrivers;platforms;iconengines;imageformats"

# The Qt plugin deploys every SQL driver it finds, and the official Qt builds ship drivers
# (Mimer, ODBC, PostgreSQL, MySQL) whose client libraries are not installed, which makes the
# deploy fail. ExtWatch only needs SQLite. On a throwaway Qt (CI) the other drivers are removed;
# elsewhere the script only says what to do.
QT_PLUGINS_DIR="$("$QMAKE" -query QT_INSTALL_PLUGINS)"
for drv in "$QT_PLUGINS_DIR"/sqldrivers/libqsql*.so; do
  [ -e "$drv" ] || continue
  case "$(basename "$drv")" in
    libqsqlite.so) ;;
    *)
      if [ -n "${CI:-}" ] || [ "${EXTWATCH_PRUNE_SQLDRIVERS:-0}" = 1 ]; then
        rm -f "$drv"
      else
        echo "note: $drv may break linuxdeploy; set EXTWATCH_PRUNE_SQLDRIVERS=1 to remove unused SQL drivers" >&2
      fi
      ;;
  esac
done
export OUTPUT="dist/ExtWatch-$VERSION-$ARCH.AppImage"
export APPIMAGE_EXTRACT_AND_RUN=1
"$TOOLS/linuxdeploy" --appdir build/AppDir --plugin qt --output appimage \
  --desktop-file build/AppDir/usr/share/applications/extwatch.desktop \
  --icon-file build/AppDir/usr/share/icons/hicolor/256x256/apps/extwatch.png
echo "built $OUTPUT"
