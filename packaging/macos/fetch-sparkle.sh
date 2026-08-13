#!/usr/bin/env bash
# Download and verify the Sparkle framework and release tools.

set -euo pipefail

readonly SPARKLE_VERSION="2.9.4"
readonly SPARKLE_SHA256="ce89daf967db1e1893ed3ebd67575ed8\
2d3902563e3191ca92aaec9164fbdef9"

temporary_dir=""

cleanup() {
  if [[ -n "${temporary_dir}" && -d "${temporary_dir}" ]]; then
    rm -rf "${temporary_dir}"
  fi
}

main() {
  if (( $# != 0 )); then
    echo "usage: $0" >&2
    return 2
  fi

  local archive_path
  local computed_sha256
  local destination
  local info_path
  local installed_version
  local project_root
  local script_dir
  local source_url

  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  project_root="$(cd "${script_dir}/../.." && pwd)"
  destination="${project_root}/build/sparkle"
  info_path="${destination}/Sparkle.framework/Versions/B/Resources/Info.plist"

  if [[ -d "${destination}/Sparkle.framework" && \
        -x "${destination}/bin/generate_appcast" && \
        -f "${destination}/LICENSE" && \
        -f "${info_path}" ]]; then
    installed_version="$(plutil -extract CFBundleShortVersionString raw \
      "${info_path}")"
    if [[ "${installed_version}" == "${SPARKLE_VERSION}" ]]; then
      return
    fi
    echo "Sparkle ${installed_version} exists at ${destination}" >&2
    echo "remove that directory to install ${SPARKLE_VERSION}" >&2
    return 1
  fi
  if [[ -e "${destination}" ]]; then
    echo "incomplete Sparkle directory: ${destination}" >&2
    return 1
  fi

  temporary_dir="$(mktemp -d /tmp/scimtest-sparkle.XXXXXX)"
  trap cleanup EXIT
  archive_path="${temporary_dir}/Sparkle-${SPARKLE_VERSION}.tar.xz"
  source_url="https://github.com/sparkle-project/Sparkle/releases/download"
  source_url+="/${SPARKLE_VERSION}/Sparkle-${SPARKLE_VERSION}.tar.xz"

  curl --fail --location --silent --show-error \
    --output "${archive_path}" \
    "${source_url}"
  computed_sha256="$(shasum -a 256 "${archive_path}" | awk '{print $1}')"
  if [[ "${computed_sha256}" != "${SPARKLE_SHA256}" ]]; then
    echo "Sparkle archive checksum mismatch" >&2
    echo "expected: ${SPARKLE_SHA256}" >&2
    echo "actual:   ${computed_sha256}" >&2
    return 1
  fi

  tar -xf "${archive_path}" -C "${temporary_dir}"
  if [[ ! -d "${temporary_dir}/Sparkle.framework" || \
        ! -x "${temporary_dir}/bin/generate_appcast" || \
        ! -f "${temporary_dir}/LICENSE" ]]; then
    echo "Sparkle archive has an unexpected layout" >&2
    return 1
  fi

  install -d "${destination}"
  ditto "${temporary_dir}/Sparkle.framework" \
    "${destination}/Sparkle.framework"
  ditto "${temporary_dir}/bin" "${destination}/bin"
  install -m 0644 "${temporary_dir}/LICENSE" "${destination}/LICENSE"
}

main "$@"
