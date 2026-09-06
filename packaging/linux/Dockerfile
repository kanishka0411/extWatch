# Linux build + test image (Debian trixie ships Qt 6.8).
FROM debian:trixie
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build git ca-certificates curl python3 file \
    qt6-base-dev qt6-base-dev-tools qt6-svg-dev libqt6sql6-sqlite qt6-qpa-plugins libgl1-mesa-dev \
    libxkbcommon-dev libfontconfig1 libdbus-1-3 fuse3 libfuse2t64 \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /src
