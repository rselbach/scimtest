#!/usr/bin/env bash
# Build the GPUI executable with release identity and package metadata.

set -euo pipefail

main() {
  if (( $# != 3 )); then
    echo "usage: $0 OUTPUT_BINARY VERSION macos|deb|rpm|pkg.tar.zst" >&2
    return 2
  fi
  local output_path="$1"
  local version="$2"
  local kind="$3"
  local project_root
  local profile_id="${SCIMTEST_APPLICATION_PROFILE_ID:-}"
  project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  if [[ ! "${version}" =~ ^[0-9]+(\.[0-9]+){0,2}$ ]]; then
    echo "invalid release version: ${version}" >&2
    return 2
  fi
  case "${kind}" in
    macos|deb|rpm|pkg.tar.zst) ;;
    *) echo "unsupported package kind: ${kind}" >&2; return 2 ;;
  esac
  if [[ ! "${profile_id}" =~ ^[a-f0-9]{32}$ ]]; then
    echo "SCIMTEST_APPLICATION_PROFILE_ID must be 32 lowercase hex digits" >&2
    return 2
  fi
  if [[ -e "${output_path}" ]]; then
    echo "output executable already exists: ${output_path}" >&2
    return 1
  fi
  if [[ "${output_path}" != /* ]]; then
    output_path="${PWD}/${output_path}"
  fi
  cd "${project_root}"
  SCIMTEST_VERSION="${version}" \
    SCIMTEST_PACKAGE_KIND="${kind}" \
    SCIMTEST_TUNNEL_PROFILE_ID="${profile_id}" \
    SCIMTEST_RELEASE_PROFILE_REQUIRED=true \
    MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-26.0}" \
    cargo build --release --locked -p scimtest-desktop
  install -d "$(dirname "${output_path}")"
  install -m 0755 \
    "${CARGO_TARGET_DIR:-target}/release/scimtest-desktop" "${output_path}"
}

main "$@"
