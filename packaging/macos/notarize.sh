#!/usr/bin/env bash
# Submit an archive to Apple's notary service and retain its full log.

set -euo pipefail

usage() {
  echo "usage: $0 ARTIFACT LOG_PATH" >&2
}

main() {
  if (( $# != 2 )); then
    usage
    return 2
  fi

  local artifact_path="$1"
  local log_path="$2"
  local result_path="${log_path%.json}-submission.json"
  local submit_status
  local submission_id

  if [[ ! -f "${artifact_path}" ]]; then
    echo "notarization artifact does not exist: ${artifact_path}" >&2
    return 1
  fi
  local credential_name
  for credential_name in \
    APPLE_ID \
    APPLE_APP_SPECIFIC_PASSWORD \
    APPLE_TEAM_ID; do
    if [[ -z "${!credential_name:-}" ]]; then
      echo "${credential_name} is required" >&2
      return 1
    fi
  done

  if xcrun notarytool submit "${artifact_path}" \
    --apple-id "${APPLE_ID}" \
    --password "${APPLE_APP_SPECIFIC_PASSWORD}" \
    --team-id "${APPLE_TEAM_ID}" \
    --wait \
    --output-format json >"${result_path}"; then
    submit_status=0
  else
    submit_status=$?
  fi
  cat "${result_path}"

  if ! submission_id="$(jq -er '.id' "${result_path}")"; then
    if (( submit_status != 0 )); then
      return "${submit_status}"
    fi
    echo "notarytool returned no submission ID" >&2
    return 1
  fi
  xcrun notarytool log "${submission_id}" \
    --apple-id "${APPLE_ID}" \
    --password "${APPLE_APP_SPECIFIC_PASSWORD}" \
    --team-id "${APPLE_TEAM_ID}" \
    "${log_path}"
  if (( submit_status != 0 )); then
    return "${submit_status}"
  fi
  jq -e '.status == "Accepted"' "${result_path}" >/dev/null
}

main "$@"
