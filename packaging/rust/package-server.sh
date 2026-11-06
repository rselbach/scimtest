#!/usr/bin/env bash
# Archive a Rust tunnel server for manual or tagged release downloads.

set -euo pipefail

stage_dir=""

cleanup() {
  if [[ -n "${stage_dir}" ]]; then
    rm -rf -- "${stage_dir}"
  fi
}

main() {
  if (( $# != 5 )); then
    echo "usage: $0 BINARY OUTPUT_DIR VERSION linux|darwin amd64|arm64" >&2
    return 2
  fi
  local binary="$1"
  local output_dir="$2"
  local version="$3"
  local platform="$4"
  local architecture="$5"
  local archive
  local project_root
  project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  if [[ ! -x "${binary}" ]]; then
    echo "server executable is missing or not executable: ${binary}" >&2
    return 1
  fi
  if [[ ! "${version}" =~ ^[0-9]+(\.[0-9]+){0,2}$ ]]; then
    echo "invalid server version: ${version}" >&2
    return 2
  fi
  case "${platform}" in
    linux|darwin) ;;
    *) echo "unsupported server platform: ${platform}" >&2; return 2 ;;
  esac
  case "${architecture}" in
    amd64|arm64) ;;
    *) echo "unsupported server architecture: ${architecture}" >&2; return 2 ;;
  esac
  archive="${output_dir}/scimtest-server_${version}_${platform}_${architecture}.tar.gz"
  if [[ -e "${archive}" ]]; then
    echo "server archive already exists: ${archive}" >&2
    return 1
  fi
  stage_dir="$(mktemp -d)"
  trap cleanup EXIT
  install -m 0755 "${binary}" "${stage_dir}/scimtest-server"
  install -m 0644 "${project_root}/LICENSE" "${stage_dir}/LICENSE"
  install -m 0644 "${project_root}/README.md" "${stage_dir}/README.md"
  install -d "${output_dir}"
  COPYFILE_DISABLE=1 tar --no-xattrs -czf "${archive}" -C "${stage_dir}" \
    scimtest-server LICENSE README.md
}

main "$@"
