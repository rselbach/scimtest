#!/usr/bin/env bash
# Verify the Linux desktop executable opens its account gate in a native window.

set -euo pipefail

app_pid=""
test_dir=""

usage() {
  echo "usage: xvfb-run -a $0 BINARY" >&2
}

cleanup() {
  if [[ -n "${app_pid:-}" ]] && kill -0 "${app_pid}" 2>/dev/null; then
    kill "${app_pid}" 2>/dev/null || true
    wait "${app_pid}" 2>/dev/null || true
  fi
  if [[ -n "${test_dir:-}" ]]; then
    rm -rf "${test_dir}"
  fi
}

main() {
  if (( $# != 1 )); then
    usage
    return 2
  fi

  local binary_path="$1"
  local exit_code=0
  local page=""
  local port="${SCIMTEST_SMOKE_PORT:-18080}"
  local -a window_ids=()

  if [[ ! -x "${binary_path}" ]]; then
    echo "desktop executable does not exist or is not executable: ${binary_path}" >&2
    return 1
  fi
  if [[ -z "${DISPLAY:-}" ]]; then
    echo "DISPLAY is not set; run this script through xvfb-run" >&2
    return 1
  fi

  test_dir="$(mktemp -d)"
  trap cleanup EXIT

  SCIMTEST_PORT="${port}" \
    SCIMTEST_STATE_FILE="${test_dir}/state.db" \
    "${binary_path}" >"${test_dir}/desktop.log" 2>&1 &
  app_pid=$!

  for _ in {1..100}; do
    if page="$(curl --fail --silent "http://127.0.0.1:${port}/" 2>/dev/null)"; then
      break
    fi
    if ! kill -0 "${app_pid}" 2>/dev/null; then
      echo "desktop process exited during startup" >&2
      if wait "${app_pid}"; then
        exit_code=0
      else
        exit_code=$?
      fi
      app_pid=""
      echo "desktop process exit status: ${exit_code}" >&2
      cat "${test_dir}/desktop.log" >&2
      return 1
    fi
    sleep 0.1
  done

  if [[ "${page}" != *"<title>Sign in to scimtest</title>"* ]]; then
    echo "desktop account gate did not load" >&2
    cat "${test_dir}/desktop.log" >&2
    return 1
  fi

  for _ in {1..100}; do
    mapfile -t window_ids \
      < <(xdotool search --name '^scimtest$' 2>/dev/null || true)
    if (( ${#window_ids[@]} > 0 )); then
      break
    fi
    sleep 0.1
  done
  if (( ${#window_ids[@]} == 0 )); then
    echo "native scimtest window was not found" >&2
    cat "${test_dir}/desktop.log" >&2
    return 1
  fi
  xdotool windowclose "${window_ids[0]}"

  for _ in {1..100}; do
    if ! kill -0 "${app_pid}" 2>/dev/null; then
      if wait "${app_pid}"; then
        exit_code=0
      else
        exit_code=$?
      fi
      app_pid=""
      if (( exit_code == 0 )); then
        return 0
      fi
      echo "desktop process exit status after window close: ${exit_code}" >&2
      cat "${test_dir}/desktop.log" >&2
      return 1
    fi
    sleep 0.1
  done

  echo "desktop process did not stop after its window closed" >&2
  cat "${test_dir}/desktop.log" >&2
  return 1
}

main "$@"
