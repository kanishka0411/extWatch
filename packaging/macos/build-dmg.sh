#!/usr/bin/env bash
# Builds ExtWatch.app and a drag-to-install .dmg. Signs and notarizes when credentials are present.
#
#   CODESIGN_IDENTITY="Developer ID Application: Name (TEAMID)"  # optional; ad-hoc signature otherwise
#   NOTARY_PROFILE=extwatch-notary                                 # optional; `xcrun notarytool store-credentials`
#   QT_PREFIX=/opt/homebrew/opt/qt                                 # optional
set -euo pipefail
cd "$(dirname "$0")/../.."
QT_PREFIX="${QT_PREFIX:-/opt/homebrew/opt/qt}"
VERSION="$(sed -n 's/.*VERSION \([0-9.]*\)$/\1/p' CMakeLists.txt | head -n1)"
DIST=dist; mkdir -p "$DIST"
STAGE_CHECK="$(mktemp)"

# Homebrew's Qt is built for macOS 14; the Qt online installer / aqtinstall builds run on 12.
MIN_MACOS="${MIN_MACOS:-$( [[ "$QT_PREFIX" == *homebrew* ]] && echo 14.0 || echo 12.0 )}"
cmake --preset release-mac -DCMAKE_PREFIX_PATH="$QT_PREFIX" -DCMAKE_OSX_DEPLOYMENT_TARGET="$MIN_MACOS" >/dev/null
APP=build/release-mac/src/ExtWatch.app
# Deploy into a clean bundle: drop the deployed frameworks/plugins and the executable itself (so it
# is relinked with its original Qt paths; macdeployqt rewrites them in place), keep Info.plist,
# which CMake writes at generate time.
rm -rf "$APP/Contents/Frameworks" "$APP/Contents/PlugIns" "$APP/Contents/Resources/qt.conf" "$APP/Contents/MacOS/ExtWatch"
cmake --build --preset release-mac
test -d "$APP" && test -f "$APP/Contents/Info.plist"

# Bundle Qt frameworks and plugins. Homebrew splits Qt into several prefixes, so give macdeployqt
# the extra library paths it needs (QtSvg backs the SVG icons).
LIBPATHS=()
for extra in "$QT_PREFIX/lib" /opt/homebrew/opt/qtsvg/lib /opt/homebrew/opt/qtbase/lib; do
  [ -d "$extra" ] && LIBPATHS+=("-libpath=$extra")
done
# macdeployqt exits non-zero when a plugin it copies references a framework it cannot find (the
# PDF image format and the virtual keyboard on Homebrew's split Qt); those plugins are pruned below.
"$QT_PREFIX/bin/macdeployqt" "$APP" -always-overwrite "${LIBPATHS[@]}" || echo "macdeployqt reported unresolved optional plugins; pruning them"

# Prune what a Widgets tray app never loads: the virtual keyboard input context (which drags in
# Qt Quick), the PDF image format, and the Quick/Qml frameworks they referenced.
rm -rf "$APP/Contents/PlugIns/platforminputcontexts" "$APP/Contents/PlugIns/imageformats/libqpdf.dylib" \
       "$APP/Contents/PlugIns/virtualkeyboard" "$APP/Contents/Resources/qml"
for fw in QtQml QtQmlMeta QtQmlModels QtQmlWorkerScript QtQuick QtQuickControls2 QtQuickTemplates2 QtOpenGL QtVirtualKeyboard QtPdf; do
  rm -rf "$APP/Contents/Frameworks/$fw.framework"
done
# Note: no lowercase "extwatch" symlink inside the bundle; macOS file systems are case-insensitive.
# For a CLI: ln -s /Applications/ExtWatch.app/Contents/MacOS/ExtWatch /usr/local/bin/extwatch

if [ -n "${CODESIGN_IDENTITY:-}" ]; then
  codesign --force --deep --options runtime --timestamp --sign "$CODESIGN_IDENTITY" "$APP"
else
  codesign --force --deep --sign - "$APP"
  echo "ad-hoc signed (set CODESIGN_IDENTITY for a Developer ID signature)"
fi
# Smoke test the bundled binary before packaging it, and make sure every @rpath framework is present.
"$APP/Contents/MacOS/ExtWatch" --version
"$APP/Contents/MacOS/ExtWatch" paths >/dev/null
for f in "$APP/Contents/MacOS/ExtWatch" "$APP"/Contents/PlugIns/*/*.dylib; do
  # After deployment, references are @executable_path/../Frameworks/...; anything still on @rpath
  # was not resolved by macdeployqt. Both must point at a framework inside the bundle.
  otool -L "$f" | grep -oE '(@rpath|@executable_path/\.\./Frameworks)/[A-Za-z0-9]+\.framework' | sed 's|.*/||' | sort -u > "$STAGE_CHECK" || true
  while read -r name; do
    [ -z "$name" ] && continue
    [ -d "$APP/Contents/Frameworks/$name" ] || { echo "missing framework $name needed by $(basename "$f")"; exit 1; }
  done < "$STAGE_CHECK"
done
rm -f "$STAGE_CHECK"

DMG="$DIST/ExtWatch-$VERSION-macos.dmg"
rm -f "$DMG"
STAGE="$(mktemp -d)"; cp -R "$APP" "$STAGE/"; ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "ExtWatch $VERSION" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null
rm -rf "$STAGE"

if [ -n "${CODESIGN_IDENTITY:-}" ]; then
  codesign --force --sign "$CODESIGN_IDENTITY" "$DMG"
  if [ -n "${NOTARY_PROFILE:-}" ]; then
    xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" --wait
    xcrun stapler staple "$DMG"
  fi
fi
echo "built $DMG"
