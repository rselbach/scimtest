#!/usr/bin/env bash
# Assemble a scimtest macOS application bundle from a desktop executable.

set -euo pipefail

usage() {
  echo "usage: $0 BINARY OUTPUT_DIR VERSION BUILD_VERSION RELEASE_NOTES" >&2
}

thin_arm64() {
  local binary_path="$1"
  local thin_path="${binary_path}.arm64"

  lipo -thin arm64 "${binary_path}" -output "${thin_path}"
  mv "${thin_path}" "${binary_path}"
}

main() {
  if (( $# != 5 )); then
    usage
    return 2
  fi

  local binary_path="$1"
  local output_dir="$2"
  local version="$3"
  local build_version="$4"
  local executable_name
  local framework_path
  local project_root
  local release_notes_path
  local script_dir
  local sparkle_path
  local app_path

  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  project_root="$(cd "${script_dir}/../.." && pwd)"
  app_path="${output_dir}/scimtest.app"
  framework_path="${project_root}/build/sparkle/Sparkle.framework"
  sparkle_path="${app_path}/Contents/Frameworks/Sparkle.framework"
  executable_name="$(plutil -extract CFBundleExecutable raw \
    "${script_dir}/Info.plist")"
  release_notes_path="$5"

  if [[ ! -f "${binary_path}" ]]; then
    echo "desktop executable does not exist: ${binary_path}" >&2
    return 1
  fi
  if [[ ! -d "${framework_path}" ]]; then
    echo "Sparkle framework does not exist: ${framework_path}" >&2
    return 1
  fi
  if [[ ! -f "${project_root}/build/sparkle/LICENSE" ]]; then
    echo "Sparkle license does not exist" >&2
    return 1
  fi
  if [[ ! -s "${release_notes_path}" ]]; then
    echo "release notes do not exist or are empty: ${release_notes_path}" >&2
    return 1
  fi
  if [[ ! "${version}" =~ ^[0-9]+(\.[0-9]+){0,2}$ ]]; then
    echo "version must contain one to three numeric components: ${version}" >&2
    return 1
  fi
  if [[ ! "${build_version}" =~ ^[0-9]+(\.[0-9]+){0,2}$ ]]; then
    echo "build version must contain one to three numeric components: ${build_version}" >&2
    return 1
  fi
  if [[ ! "${executable_name}" =~ ^[a-zA-Z0-9._-]+$ ]]; then
    echo "invalid CFBundleExecutable: ${executable_name}" >&2
    return 1
  fi
  if [[ -e "${app_path}" ]]; then
    echo "application bundle already exists: ${app_path}" >&2
    return 1
  fi

  install -d \
    "${app_path}/Contents/Frameworks" \
    "${app_path}/Contents/MacOS" \
    "${app_path}/Contents/Resources/ThirdPartyLicenses"
  install -m 0755 "${binary_path}" \
    "${app_path}/Contents/MacOS/${executable_name}"
  install -m 0644 "${script_dir}/Info.plist" \
    "${app_path}/Contents/Info.plist"
  install -m 0644 "${script_dir}/AppIcon.icns" \
    "${app_path}/Contents/Resources/AppIcon.icns"
  install -m 0644 "${project_root}/build/sparkle/LICENSE" \
    "${app_path}/Contents/Resources/ThirdPartyLicenses/Sparkle.txt"
  install -m 0644 "${release_notes_path}" \
    "${app_path}/Contents/Resources/ReleaseNotes.md"
  ditto "${framework_path}" "${sparkle_path}"
  rm -rf "${sparkle_path}/Versions/B/XPCServices"
  rm -f "${sparkle_path}/XPCServices"
  thin_arm64 "${sparkle_path}/Versions/B/Autoupdate"
  thin_arm64 \
    "${sparkle_path}/Versions/B/Updater.app/Contents/MacOS/Updater"
  thin_arm64 "${sparkle_path}/Versions/B/Sparkle"

  install_name_tool -add_rpath \
    @executable_path/../Frameworks \
    "${app_path}/Contents/MacOS/${executable_name}"

  plutil -replace CFBundleShortVersionString -string "${version}" \
    "${app_path}/Contents/Info.plist"
  plutil -replace CFBundleVersion -string "${build_version}" \
    "${app_path}/Contents/Info.plist"
  plutil -lint "${app_path}/Contents/Info.plist"
}

main "$@"
