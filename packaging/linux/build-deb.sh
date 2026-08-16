#!/usr/bin/env bash
# Package the Linux desktop executable as a Debian package.

set -euo pipefail

stage_dir=""

usage() {
  echo "usage: $0 BINARY OUTPUT_DEB VERSION ARCHITECTURE" >&2
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
  local binary_path="$1"
  local output_path="$2"
  local project_root
  local script_dir
  local version="$3"

  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  project_root="$(cd "${script_dir}/../.." && pwd)"

  if [[ ! -x "${binary_path}" ]]; then
    echo "desktop executable does not exist or is not executable: ${binary_path}" >&2
    return 1
  fi
  if [[ "${architecture}" != "amd64" && "${architecture}" != "arm64" ]]; then
    echo "unsupported Debian architecture: ${architecture}" >&2
    return 1
  fi
  if ! dpkg --validate-version "${version}"; then
    echo "invalid Debian package version: ${version}" >&2
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

  stage_dir="$(mktemp -d)"
  trap cleanup EXIT

  install -d \
    "${stage_dir}/DEBIAN" \
    "${stage_dir}/usr/bin" \
    "${stage_dir}/usr/share/applications" \
    "${stage_dir}/usr/share/doc/scimtest-desktop" \
    "${stage_dir}/usr/share/icons/hicolor/1024x1024/apps"
  install -m 0755 "${binary_path}" \
    "${stage_dir}/usr/bin/scimtest-desktop"
  install -m 0644 "${script_dir}/com.rselbach.scimtest.desktop" \
    "${stage_dir}/usr/share/applications/com.rselbach.scimtest.desktop"
  install -m 0644 "${project_root}/packaging/macos/AppIcon.png" \
    "${stage_dir}/usr/share/icons/hicolor/1024x1024/apps/scimtest.png"
  install -m 0644 "${project_root}/LICENSE" \
    "${stage_dir}/usr/share/doc/scimtest-desktop/copyright"

  cat >"${stage_dir}/DEBIAN/control" <<EOF
Package: scimtest-desktop
Version: ${version}
Section: devel
Priority: optional
Architecture: ${architecture}
Maintainer: scimtest maintainers <rselbach@users.noreply.github.com>
Depends: ca-certificates, libgtk-3-0t64, libwebkit2gtk-4.1-0, xdg-utils
Description: Local SCIM, OIDC, and SAML integration testing
 scimtest provides a desktop interface for testing identity provider and SCIM
 integrations without connecting the application under test to a production
 identity provider.
EOF

  dpkg-deb --root-owner-group --build "${stage_dir}" "${output_path}"
}

main "$@"
