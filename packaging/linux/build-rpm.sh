#!/usr/bin/env bash
# Package the Linux desktop executable as an RPM package.

set -euo pipefail

top_dir=""

usage() {
  echo "usage: $0 BINARY OUTPUT_RPM VERSION ARCHITECTURE" >&2
}

cleanup() {
  if [[ -n "${top_dir:-}" ]]; then
    rm -rf "${top_dir}"
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
  local rpm_arch
  local rpm_path
  local rpm_version
  local script_dir
  local version="$3"
  local -a rpm_paths=()

  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  project_root="$(cd "${script_dir}/../.." && pwd)"
  binary_path="$(realpath "${binary_path}")"
  output_path="$(realpath -m "${output_path}")"

  if [[ ! -x "${binary_path}" ]]; then
    echo "desktop executable does not exist or is not executable: ${binary_path}" >&2
    return 1
  fi
  case "${architecture}" in
    amd64) rpm_arch="x86_64" ;;
    arm64) rpm_arch="aarch64" ;;
    *)
      echo "unsupported RPM architecture: ${architecture}" >&2
      return 1
      ;;
  esac

  rpm_version="${version//-/~}"
  if [[ ! "${rpm_version}" =~ ^[[:alnum:].+~]+$ ]]; then
    echo "invalid RPM package version: ${version}" >&2
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
  if ! command -v rpmbuild >/dev/null; then
    echo "rpmbuild is required to build the RPM package" >&2
    return 1
  fi

  top_dir="$(mktemp -d)"
  trap cleanup EXIT
  install -d "${top_dir}/BUILD" "${top_dir}/BUILDROOT" \
    "${top_dir}/RPMS" "${top_dir}/SOURCES" "${top_dir}/SPECS" \
    "${top_dir}/SRPMS"

  cat >"${top_dir}/SPECS/scimtest-desktop.spec" <<EOF
%global debug_package %{nil}

Name: scimtest-desktop
Version: ${rpm_version}
Release: 1%{?dist}
Summary: Local SCIM, OIDC, and SAML integration testing
License: Apache-2.0
URL: https://github.com/rselbach/scimtest
BuildArch: ${rpm_arch}
Requires: ca-certificates
Requires: gtk3
Requires: webkit2gtk4.1
Requires: xdg-utils

%description
scimtest provides a desktop interface for testing identity provider and SCIM
integrations without connecting the application under test to a production
identity provider.

%prep

%build

%install
install -Dpm0755 "${binary_path}" \
  "%{buildroot}/usr/bin/scimtest-desktop"
install -Dpm0644 "${script_dir}/com.rselbach.scimtest.desktop" \
  "%{buildroot}/usr/share/applications/com.rselbach.scimtest.desktop"
install -Dpm0644 "${project_root}/packaging/macos/AppIcon.png" \
  "%{buildroot}/usr/share/icons/hicolor/1024x1024/apps/scimtest.png"
install -Dpm0644 "${project_root}/LICENSE" \
  "%{buildroot}/usr/share/licenses/scimtest-desktop/LICENSE"

%files
%license /usr/share/licenses/scimtest-desktop/LICENSE
/usr/bin/scimtest-desktop
/usr/share/applications/com.rselbach.scimtest.desktop
/usr/share/icons/hicolor/1024x1024/apps/scimtest.png
EOF

  rpmbuild -bb \
    --define "_topdir ${top_dir}" \
    "${top_dir}/SPECS/scimtest-desktop.spec"

  mapfile -t rpm_paths \
    < <(find "${top_dir}/RPMS/${rpm_arch}" -maxdepth 1 -type f -name '*.rpm')
  if (( ${#rpm_paths[@]} != 1 )); then
    echo "expected one RPM package, found ${#rpm_paths[@]}" >&2
    return 1
  fi
  rpm_path="${rpm_paths[0]}"
  install -m 0644 "${rpm_path}" "${output_path}"
}

main "$@"
