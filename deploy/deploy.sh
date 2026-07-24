#!/usr/bin/env bash
# Build and deploy scimtest-server to its exe.dev VM.

set -Eeuo pipefail

readonly DEPLOY_HOST="scimtest.exe.xyz"
readonly SERVICE_NAME="scimtest-server.service"
readonly REMOTE_BINARY="/usr/local/bin/scimtest-server"
readonly REMOTE_ENV="/etc/scimtest-server/scimtest-server.env"
readonly REMOTE_UNIT="/etc/systemd/system/${SERVICE_NAME}"

local_tmp_dir=""
remote_tmp_dir=""

cleanup() {
  local exit_code=$?

  if [[ "${remote_tmp_dir}" == /tmp/scimtest-deploy.* ]]; then
    ssh "${DEPLOY_HOST}" rm -rf -- "${remote_tmp_dir}" || true
  fi
  if [[ -n "${local_tmp_dir}" ]]; then
    rm -rf -- "${local_tmp_dir}"
  fi

  return "${exit_code}"
}

require_command() {
  local command_name=$1

  if command -v "${command_name}" >/dev/null; then
    return
  fi

  echo "error: required command not found: ${command_name}" >&2
  return 1
}

deploy() {
  remote_tmp_dir="$(
    ssh "${DEPLOY_HOST}" mktemp -d /tmp/scimtest-deploy.XXXXXX
  )"

  scp \
    "${local_tmp_dir}/scimtest-server" \
    deploy/scimtest-server.service \
    "${DEPLOY_HOST}:${remote_tmp_dir}/"

  ssh "${DEPLOY_HOST}" bash -s -- \
    "${remote_tmp_dir}" \
    "${REMOTE_BINARY}" \
    "${REMOTE_ENV}" \
    "${REMOTE_UNIT}" \
    "${SERVICE_NAME}" <<'REMOTE_SCRIPT'
set -Eeuo pipefail

readonly deploy_dir=$1
readonly binary_path=$2
readonly env_path=$3
readonly unit_path=$4
readonly service_name=$5
readonly backup_binary="${deploy_dir}/scimtest-server.previous"
readonly backup_unit="${deploy_dir}/scimtest-server.service.previous"

had_binary=false
had_unit=false

rollback() {
  local exit_code=$?

  trap - ERR
  echo "error: deployment failed; restoring the previous service" >&2

  if [[ "${had_binary}" == true ]]; then
    sudo install -m 0755 "${backup_binary}" "${binary_path}"
  else
    sudo rm -f -- "${binary_path}"
  fi

  if [[ "${had_unit}" == true ]]; then
    sudo install -m 0644 "${backup_unit}" "${unit_path}"
  else
    sudo rm -f -- "${unit_path}"
  fi

  sudo systemctl daemon-reload || true
  if [[ "${had_unit}" == true ]]; then
    sudo systemctl restart "${service_name}" || true
  fi

  exit "${exit_code}"
}

verify_service() {
  local attempt

  for ((attempt = 1; attempt <= 10; attempt++)); do
    if sudo systemctl is-active --quiet "${service_name}" \
      && curl -fsS --max-time 2 \
        -H 'Host: scimtest.rselbach.com' \
        http://127.0.0.1:8000/ >/dev/null; then
      return
    fi
    sleep 1
  done

  sudo systemctl status "${service_name}" --no-pager -l >&2 || true
  sudo journalctl -u "${service_name}" -n 50 --no-pager >&2 || true
  return 1
}

if ! sudo test -f "${env_path}"; then
  echo "error: missing server environment file: ${env_path}" >&2
  exit 1
fi

if sudo test -f "${binary_path}"; then
  sudo cp --preserve=mode,ownership "${binary_path}" "${backup_binary}"
  had_binary=true
fi
if sudo test -f "${unit_path}"; then
  sudo cp --preserve=mode,ownership "${unit_path}" "${backup_unit}"
  had_unit=true
fi

trap rollback ERR

sudo install -m 0755 \
  "${deploy_dir}/scimtest-server" \
  "${binary_path}"
sudo install -m 0644 \
  "${deploy_dir}/scimtest-server.service" \
  "${unit_path}"
sudo systemctl daemon-reload
sudo systemctl enable "${service_name}"
sudo systemctl restart "${service_name}"
verify_service

trap - ERR
REMOTE_SCRIPT
}

main() {
  require_command go
  require_command scp
  require_command ssh

  local_tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/scimtest-deploy.XXXXXX")"
  trap cleanup EXIT

  echo "Building scimtest-server for linux/amd64"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath \
      -o "${local_tmp_dir}/scimtest-server" \
      ./cmd/scimtest-server

  echo "Deploying to ${DEPLOY_HOST}"
  deploy
  echo "Deployment healthy: https://scimtest.rselbach.com"
}

main "$@"
