#!/usr/bin/env bash
# Package the Linux desktop executable for installation with pacman.

set -euo pipefail

stage_dir=""

usage() {
  echo "usage: $0 BINARY OUTPUT_PACKAGE VERSION ARCHITECTURE" >&2
}

cleanup() {
  if [[ -n "${stage_dir:-}" ]]; then
    rm -rf "${stage_dir}"
  fi
}

main() {
  if (( $# != 4 )); then
    usage
    return 2
  fi

  local architecture="$4"
  local arch_package
  local arch_version
  local binary_path="$1"
  local binary_sha256
  local desktop_sha256
  local icon_sha256
  local license_sha256
  local output_path="$2"
  local package_path
  local project_root
  local script_dir
  local version="$3"
  local -a package_paths=()

  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  project_root="$(cd "${script_dir}/../.." && pwd)"
  binary_path="$(realpath "${binary_path}")"
  output_path="$(realpath -m "${output_path}")"

  if [[ ! -x "${binary_path}" ]]; then
    echo "desktop executable does not exist or is not executable: ${binary_path}" >&2
    return 1
  fi
  case "${architecture}" in
    amd64) arch_package="x86_64" ;;
    arm64) arch_package="aarch64" ;;
    *)
      echo "unsupported Arch package architecture: ${architecture}" >&2
      return 1
      ;;
  esac

  arch_version="${version//-/_}"
  if [[ ! "${arch_version}" =~ ^[[:alnum:].+_]+$ ]]; then
    echo "invalid Arch package version: ${version}" >&2
    return 1
  fi
  if [[ ! -d "$(dirname "${output_path}")" ]]; then
    echo "output directory does not exist: $(dirname "${output_path}")" >&2
    return 1
  fi
  if [[ -e "${output_path}" ]]; then
    echo "output package already exists: ${output_path}" >&2
    return 1
  fi
  if (( EUID == 0 )); then
    echo "makepkg cannot run as root; run this script as an unprivileged user" >&2
    return 1
  fi
  if ! command -v makepkg >/dev/null; then
    echo "makepkg is required to build the Arch package" >&2
    return 1
  fi

  stage_dir="$(mktemp -d)"
  trap cleanup EXIT
  install -d "${stage_dir}/out"
  install -m 0755 "${binary_path}" "${stage_dir}/scimtest-desktop"
  install -m 0644 "${script_dir}/com.rselbach.scimtest.desktop" \
    "${stage_dir}/com.rselbach.scimtest.desktop"
  install -m 0644 "${project_root}/packaging/macos/AppIcon.png" \
    "${stage_dir}/scimtest.png"
  install -m 0644 "${project_root}/LICENSE" "${stage_dir}/LICENSE"

  binary_sha256="$(sha256sum "${stage_dir}/scimtest-desktop" | cut -d ' ' -f 1)"
  desktop_sha256="$(sha256sum "${stage_dir}/com.rselbach.scimtest.desktop" | cut -d ' ' -f 1)"
  icon_sha256="$(sha256sum "${stage_dir}/scimtest.png" | cut -d ' ' -f 1)"
  license_sha256="$(sha256sum "${stage_dir}/LICENSE" | cut -d ' ' -f 1)"

  cat >"${stage_dir}/PKGBUILD" <<EOF
pkgname=scimtest-desktop
pkgver=${arch_version}
pkgrel=1
pkgdesc='Local SCIM, OIDC, and SAML integration testing'
arch=('${arch_package}')
url='https://github.com/rselbach/scimtest'
license=('Apache-2.0')
depends=('ca-certificates' 'gtk3' 'webkit2gtk-4.1' 'xdg-utils')
options=('!debug')
source=('scimtest-desktop' 'com.rselbach.scimtest.desktop' 'scimtest.png' 'LICENSE')
sha256sums=('${binary_sha256}' '${desktop_sha256}' '${icon_sha256}' '${license_sha256}')

package() {
  install -Dpm0755 "\${srcdir}/scimtest-desktop" \
    "\${pkgdir}/usr/bin/scimtest-desktop"
  install -Dpm0644 "\${srcdir}/com.rselbach.scimtest.desktop" \
    "\${pkgdir}/usr/share/applications/com.rselbach.scimtest.desktop"
  install -Dpm0644 "\${srcdir}/scimtest.png" \
    "\${pkgdir}/usr/share/icons/hicolor/1024x1024/apps/scimtest.png"
  install -Dpm0644 "\${srcdir}/LICENSE" \
    "\${pkgdir}/usr/share/licenses/scimtest-desktop/LICENSE"
}
EOF

  (
    cd "${stage_dir}"
    PKGDEST="${stage_dir}/out" makepkg --clean --force --nodeps
  )

  mapfile -t package_paths \
    < <(find "${stage_dir}/out" -maxdepth 1 -type f -name '*.pkg.tar.zst')
  if (( ${#package_paths[@]} != 1 )); then
    echo "expected one Arch package, found ${#package_paths[@]}" >&2
    return 1
  fi
  package_path="${package_paths[0]}"
  install -m 0644 "${package_path}" "${output_path}"
}

main "$@"
