#!/usr/bin/env bash
# Deploys the download page in site/ to https://rselbach.com/scimtest/ on the
# rselbach exe.dev VM: syncs the files, installs the nginx snippet, reloads
# nginx when its configuration tests clean, and checks the live page.
set -euo pipefail

readonly HOST="rselbach.exe.xyz"
readonly WEB_DIR="/var/www/scimtest"
readonly SNIPPET="/etc/nginx/snippets/scimtest.conf"
readonly SERVER_CONF="/etc/nginx/sites-enabled/default"
readonly URL="https://rselbach.com/scimtest/"

die() {
  echo "deploy-site: $*" >&2
  exit 1
}

# runs on the VM: installs the snippet, includes it in the rselbach.com server
# block once, and rolls both files back if nginx rejects the result
configure_nginx() {
  # shellcheck disable=SC2087 # expand the constants locally on purpose
  ssh "${HOST}" bash -s <<REMOTE
set -euo pipefail
backup="\$(mktemp -d)"
sudo cp -p "${SERVER_CONF}" "\${backup}/server.conf"
if [[ -f "${SNIPPET}" ]]; then
  sudo cp -p "${SNIPPET}" "\${backup}/snippet.conf"
fi
restore() {
  sudo cp -p "\${backup}/server.conf" "${SERVER_CONF}"
  if [[ -f "\${backup}/snippet.conf" ]]; then
    sudo cp -p "\${backup}/snippet.conf" "${SNIPPET}"
  else
    sudo rm -f "${SNIPPET}"
  fi
}

sudo install -m 644 /tmp/scimtest-site-nginx.conf "${SNIPPET}"
rm -f /tmp/scimtest-site-nginx.conf
if ! grep -qF "include ${SNIPPET};" "${SERVER_CONF}"; then
  if (( \$(grep -c '^ *server_name rselbach.com;' "${SERVER_CONF}") != 1 )); then
    echo "expected one 'server_name rselbach.com;' in ${SERVER_CONF}" >&2
    exit 1
  fi
  sudo sed -i '/^ *server_name rselbach.com;/a\\    include ${SNIPPET};' \\
    "${SERVER_CONF}"
fi

if ! sudo nginx -t 2>"\${backup}/nginx-t.log"; then
  cat "\${backup}/nginx-t.log" >&2
  restore
  echo "nginx rejected the configuration; restored the previous files" >&2
  exit 1
fi
sudo systemctl reload nginx
sudo rm -rf "\${backup}"
REMOTE
}

# fails unless the live page, its redirect, its script, and the blog respond
verify() {
  local headers
  headers="$(curl -fsSI "${URL}")" || die "${URL} did not return 2xx"
  grep -qi '^content-security-policy:.*connect-src https://rselbach.github.io' \
    <<<"${headers}" || die "${URL} is missing the expected CSP"

  local location
  location="$(curl -sS -o /dev/null -w '%{redirect_url}' "${URL%/}")"
  [[ "${location}" == "${URL}" ]] || die "${URL%/} redirects to '${location}'"

  local file
  for file in site.js screenshot.webp icon.png; do
    curl -fsS -o /dev/null "${URL}${file}" || die "${URL}${file} failed"
  done
  curl -fsS -o /dev/null "https://rselbach.com/" || die "the blog root failed"
  echo "deployed ${URL}"
}

main() {
  local repo
  repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  [[ -f "${repo}/site/index.html" ]] || die "site/index.html not found"

  # shellcheck disable=SC2029 # WEB_DIR is a local constant
  ssh "${HOST}" "sudo install -d -o exedev -g www-data -m 755 '${WEB_DIR}'"
  rsync -rlt --delete --delay-updates "${repo}/site/" "${HOST}:${WEB_DIR}/"
  # shellcheck disable=SC2029 # WEB_DIR is a local constant
  ssh "${HOST}" "chmod -R u=rwX,go=rX '${WEB_DIR}'"
  scp -q "${repo}/deploy/site-nginx.conf" "${HOST}:/tmp/scimtest-site-nginx.conf"
  configure_nginx
  verify
}

main "$@"
