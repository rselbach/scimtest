#!/usr/bin/env bash
# Publish the current desktop release to the personal Homebrew tap.

set -euo pipefail

checkout_dir=""

cleanup() {
  if [[ -n "${checkout_dir}" && -d "${checkout_dir}" ]]; then
    rm -rf "${checkout_dir}"
  fi
}

usage() {
  echo "usage: $0 VERSION DMG_SHA256" >&2
}

main() {
  if (( $# != 2 )); then
    usage
    return 2
  fi

  local version="$1"
  local dmg_sha256="$2"
  local script_dir
  local cask_path
  local cask_status
  local legacy_cask_path

  if [[ ! "${version}" =~ ^[0-9]+(\.[0-9]+){0,2}$ ]]; then
    echo "invalid cask version: ${version}" >&2
    return 1
  fi
  if [[ ! "${dmg_sha256}" =~ ^[a-f0-9]{64}$ ]]; then
    echo "invalid DMG SHA-256: ${dmg_sha256}" >&2
    return 1
  fi
  if [[ -z "${GH_TOKEN:-}" ]]; then
    echo "GH_TOKEN is required to update the Homebrew tap" >&2
    return 1
  fi

  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  checkout_dir="$(mktemp -d /tmp/scimtest-homebrew-tap.XXXXXX)"
  trap cleanup EXIT
  cask_path="${checkout_dir}/Casks/scimtest-desktop.rb"
  legacy_cask_path="${checkout_dir}/Casks/scimtest.rb"

  gh auth setup-git
  gh repo clone rselbach/homebrew-tap "${checkout_dir}" -- --depth=1
  install -d "${checkout_dir}/Casks"
  sed \
    -e "s/__VERSION__/${version}/g" \
    -e "s/__SHA256__/${dmg_sha256}/g" \
    "${script_dir}/scimtest-desktop.rb.tmpl" >"${cask_path}"
  if [[ -f "${legacy_cask_path}" ]]; then
    git -C "${checkout_dir}" rm "Casks/scimtest.rb"
  fi

  cask_status="$(git -C "${checkout_dir}" status --short -- \
    "Casks/scimtest-desktop.rb" "Casks/scimtest.rb")"
  if [[ -z "${cask_status}" ]]; then
    echo "Homebrew cask is already current"
    return
  fi

  git -C "${checkout_dir}" config user.name "github-actions[bot]"
  git -C "${checkout_dir}" config user.email \
    "41898282+github-actions[bot]@users.noreply.github.com"
  git -C "${checkout_dir}" add "Casks/scimtest-desktop.rb"
  git -C "${checkout_dir}" commit -m \
    "Update scimtest-desktop to ${version}"
  git -C "${checkout_dir}" push
}

main "$@"
