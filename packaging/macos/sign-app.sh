#!/usr/bin/env bash
# Sign scimtest and Sparkle from the innermost helpers outward.

set -euo pipefail

usage() {
  echo "usage: $0 APP_PATH SIGNING_IDENTITY [--timestamp]" >&2
}

sign_target() {
  local signing_identity="$1"
  local use_timestamp="$2"
  local target="$3"
  local flags=(
    --force
    --options runtime
    --sign "${signing_identity}"
  )

  if [[ "${use_timestamp}" == true ]]; then
    flags+=(--timestamp)
  fi
  codesign "${flags[@]}" "${target}"
}

main() {
  if (( $# < 2 || $# > 3 )); then
    usage
    return 2
  fi

  local app_path="$1"
  local signing_identity="$2"
  local use_timestamp=false
  local sparkle_path

  if (( $# == 3 )); then
    if [[ "$3" != "--timestamp" ]]; then
      usage
      return 2
    fi
    use_timestamp=true
  fi
  if [[ ! -d "${app_path}" || "${app_path}" != *.app ]]; then
    echo "application bundle does not exist: ${app_path}" >&2
    return 1
  fi

  sparkle_path="${app_path}/Contents/Frameworks/Sparkle.framework"
  if [[ ! -d "${sparkle_path}" ]]; then
    echo "Sparkle framework does not exist: ${sparkle_path}" >&2
    return 1
  fi

  sign_target "${signing_identity}" "${use_timestamp}" \
    "${sparkle_path}/Versions/B/Autoupdate"
  sign_target "${signing_identity}" "${use_timestamp}" \
    "${sparkle_path}/Versions/B/Updater.app"
  sign_target "${signing_identity}" "${use_timestamp}" "${sparkle_path}"
  sign_target "${signing_identity}" "${use_timestamp}" "${app_path}"
}

main "$@"
