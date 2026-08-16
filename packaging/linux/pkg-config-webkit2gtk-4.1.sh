#!/usr/bin/env bash
# Build webview_go against WebKitGTK 4.1 instead of its legacy pkg-config name.

set -euo pipefail

main() {
  local -a args=()
  local arg

  for arg in "$@"; do
    if [[ "${arg}" == "webkit2gtk-4.0" ]]; then
      arg="webkit2gtk-4.1"
    fi
    args+=("${arg}")
  done

  exec pkg-config "${args[@]}"
}

main "$@"
