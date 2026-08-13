#!/usr/bin/env bash
# Create a simple drag-to-Applications disk image for scimtest.

set -euo pipefail

stage_dir=""

cleanup() {
  if [[ -n "${stage_dir}" && -d "${stage_dir}" ]]; then
    rm -rf "${stage_dir}"
  fi
}

usage() {
  echo "usage: $0 APP_PATH OUTPUT_DMG" >&2
}

main() {
  if (( $# != 2 )); then
    usage
    return 2
  fi

  local app_path="$1"
  local output_path="$2"

  if [[ ! -d "${app_path}" || "${app_path}" != *.app ]]; then
    echo "application bundle does not exist: ${app_path}" >&2
    return 1
  fi
  if [[ -e "${output_path}" ]]; then
    echo "disk image already exists: ${output_path}" >&2
    return 1
  fi

  stage_dir="$(mktemp -d /tmp/scimtest-dmg.XXXXXX)"
  trap cleanup EXIT

  cp -R "${app_path}" "${stage_dir}/scimtest.app"
  ln -s /Applications "${stage_dir}/Applications"
  hdiutil create \
    -volname scimtest \
    -srcfolder "${stage_dir}" \
    -format UDZO \
    "${output_path}"
}

main "$@"
