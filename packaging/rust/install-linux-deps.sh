#!/usr/bin/env bash
# Install the desktop build and smoke-test dependencies on supported CI images.

set -euo pipefail

main() {
  local elevate=()
  if (( EUID != 0 )); then
    elevate=(sudo)
  fi
  if command -v apt-get >/dev/null; then
    "${elevate[@]}" apt-get update
    "${elevate[@]}" apt-get install -y \
      build-essential clang cmake curl git pkg-config python3 \
      libfontconfig1-dev libfreetype-dev libssl-dev libxcb1-dev \
      libxkbcommon-dev libxkbcommon-x11-dev libwayland-dev \
      libvulkan-dev mesa-vulkan-drivers fonts-dejavu-core \
      xdotool xvfb xauth dbus-x11
    return
  fi
  if command -v dnf >/dev/null; then
    "${elevate[@]}" dnf install -y \
      gcc-c++ clang cmake curl git pkgconf-pkg-config python3 \
      fontconfig-devel freetype-devel openssl-devel libxcb-devel \
      libxkbcommon-devel libxkbcommon-x11-devel wayland-devel \
      vulkan-loader-devel mesa-vulkan-drivers dejavu-sans-fonts \
      xdotool xorg-x11-server-Xvfb xorg-x11-xauth dbus-daemon \
      rpm-build findutils tar gzip which
    return
  fi
  if command -v pacman >/dev/null; then
    "${elevate[@]}" pacman -Syu --noconfirm \
      base-devel clang cmake curl git pkgconf python openssl \
      fontconfig freetype2 libxcb libxkbcommon libxkbcommon-x11 wayland \
      vulkan-headers vulkan-icd-loader vulkan-swrast ttf-dejavu \
      xdotool xorg-server-xvfb xorg-xauth dbus
    return
  fi
  echo "unsupported distribution: apt-get, dnf, or pacman is required" >&2
  return 1
}

main "$@"
