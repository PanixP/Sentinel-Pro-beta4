#!/bin/bash
set -euo pipefail

VERSION="v4.3b1-pro"
REPO_OWNER="${SENTINEL_REPO_OWNER:-PanixP}"
REPO_NAME="${SENTINEL_REPO_NAME:-Sentinel-Pro-beta4}"
REPO_BRANCH="${SENTINEL_REPO_BRANCH:-main}"
RAW_BASE_URL="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_BRANCH}"
RUBI_INSTALL_URL="https://github.com/benumc/rubi/raw/main/rubi.sh"

SENTINEL_WRITABLE_ROOT="/home/RPM"
TARGET_ROOT="${SENTINEL_TARGET_ROOT:-${SENTINEL_WRITABLE_ROOT}/Sentinel}"
CUSTOMER_FILES_ROOT="/home/RPM/GNUstep/Library/ApplicationSupport/RacePointMedia"
CUSTOMER_FILES_DIR="${SENTINEL_CUSTOMER_FILES_DIR:-${CUSTOMER_FILES_ROOT}/userConfig.rpmConfig/CustomerFiles}"

BRIDGE_FILE="savant_network_sentinel_clean_rubi_bridge_v4_3b1_pro.rb"
MANUAL_FILE="manual_bridge_diagnose_v4_3b1_pro.sh"
PROBE_FILE="probe_sclibridge_v4_3b1_pro.sh"
COMPAT_FILE="rubi_compat_v4_3b1_pro.sh"
EXAMPLE_MANIFEST="example_harvest_manifest.txt"
BLUEPRINT_GEN="generate_harvest_manifest_from_blueprint.rb"
RPMCONFIG_GEN="generate_harvest_manifest_from_rpmconfig.rb"

say() {
  printf '%s\n' "$*"
}

fetch_or_copy() {
  local file_name="$1"
  local destination="$2"
  local local_source="${CUSTOMER_FILES_DIR}/${file_name}"
  local temp_file
  temp_file="$(mktemp "/tmp/sentinel_${file_name}.XXXXXX")"

  if [[ -r "${local_source}" ]]; then
    say "[local] ${file_name} <= ${local_source}"
    cp "${local_source}" "${temp_file}"
  else
    say "[curl]  ${file_name} <= ${RAW_BASE_URL}/${file_name}"
    curl -fsSL "${RAW_BASE_URL}/${file_name}" -o "${temp_file}"
  fi

  mv "${temp_file}" "${destination}"
}

ensure_target_writable() {
  local test_file="${TARGET_ROOT}/.sentinel_write_test.$$"
  if ! ( : > "${test_file}" ) 2>/dev/null; then
    say "[error] target path is not writable: ${TARGET_ROOT}"
    say "[error] set SENTINEL_TARGET_ROOT to a writable folder and retry."
    exit 1
  fi
  rm -f "${test_file}"
}

install_upstream_rubi() {
  say "[curl]  benumc/rubi.sh <= ${RUBI_INSTALL_URL}"
  curl -fsSL "${RUBI_INSTALL_URL}" | bash
  say "[ok]    rubi trigger installer completed"
}

main() {
  say "== Sentinel Savant Rubi Bridge (${VERSION}) first install (SmartHosts layout) =="
  say "Target root:   ${TARGET_ROOT}"
  say "CustomerFiles: ${CUSTOMER_FILES_DIR}"
  say

  mkdir -p "${TARGET_ROOT}" "${TARGET_ROOT}/logs"
  ensure_target_writable
  install_upstream_rubi

  fetch_or_copy "${BRIDGE_FILE}" "${TARGET_ROOT}/${BRIDGE_FILE}"
  fetch_or_copy "${MANUAL_FILE}" "${TARGET_ROOT}/${MANUAL_FILE}"
  fetch_or_copy "${PROBE_FILE}" "${TARGET_ROOT}/${PROBE_FILE}"
  fetch_or_copy "${COMPAT_FILE}" "${TARGET_ROOT}/${COMPAT_FILE}"
  fetch_or_copy "${EXAMPLE_MANIFEST}" "${TARGET_ROOT}/${EXAMPLE_MANIFEST}"
  fetch_or_copy "${BLUEPRINT_GEN}" "${TARGET_ROOT}/${BLUEPRINT_GEN}"
  fetch_or_copy "${RPMCONFIG_GEN}" "${TARGET_ROOT}/${RPMCONFIG_GEN}"

  chmod 644 "${TARGET_ROOT}/${BRIDGE_FILE}" "${TARGET_ROOT}/${EXAMPLE_MANIFEST}" "${TARGET_ROOT}/${BLUEPRINT_GEN}" "${TARGET_ROOT}/${RPMCONFIG_GEN}"
  chmod 755 "${TARGET_ROOT}/${MANUAL_FILE}" "${TARGET_ROOT}/${PROBE_FILE}" "${TARGET_ROOT}/${COMPAT_FILE}"
  chmod 755 "${TARGET_ROOT}" "${TARGET_ROOT}/logs"

  if [[ ! -f "${TARGET_ROOT}/harvest_manifest.txt" ]]; then
    cp "${TARGET_ROOT}/${EXAMPLE_MANIFEST}" "${TARGET_ROOT}/harvest_manifest.txt"
    chmod 644 "${TARGET_ROOT}/harvest_manifest.txt"
    say "[init]  harvest_manifest.txt created"
  fi

  say
  say "Installed:"
  say "- ${TARGET_ROOT}/${BRIDGE_FILE}"
  say "- ${TARGET_ROOT}/${MANUAL_FILE}"
  say "- ${TARGET_ROOT}/${PROBE_FILE}"
  say "- ${TARGET_ROOT}/${COMPAT_FILE}"
  say "- ${TARGET_ROOT}/${EXAMPLE_MANIFEST}"
  say "- ${TARGET_ROOT}/harvest_manifest.txt"
  say
  say "Use XML:"
  say "- local_script_path=${TARGET_ROOT}/"
  say "- script_file=${BRIDGE_FILE}"
  say "- harvest_max_states=7000"
}

main "$@"
