#!/usr/bin/env bash
# Builds and tests ExtWatch inside Debian trixie, then builds the AppImage. Output lands in dist/.
set -euo pipefail
cd "$(dirname "$0")/../.."
docker build -t extwatch-linux-build -f packaging/linux/Dockerfile packaging/linux
docker run --rm -v "$PWD:/src" -w /src extwatch-linux-build bash -lc '
  set -euo pipefail
  cmake --preset dev-linux -DCMAKE_BUILD_TYPE=Release
  cmake --build --preset dev-linux
  QT_QPA_PLATFORM=offscreen ctest --preset dev-linux
  ./build/dev-linux/src/extwatch --version
  ./build/dev-linux/src/extwatch analyze fixtures/extensions/screenshot-tool/1.2.0 --json | head -c 200; echo
  packaging/linux/build-appimage.sh || echo "AppImage step failed (needs FUSE or network); binary is at build/dev-linux/src/extwatch"
'
