#!/bin/bash
set -euo pipefail

VERSION="v4.3b1-pro"
REPO_OWNER="${SENTINEL_REPO_OWNER:-PanixP}"
REPO_NAME="${SENTINEL_REPO_NAME:-Sentinel-Pro-beta4}"
REPO_BRANCH="${SENTINEL_REPO_BRANCH:-main}"
RAW_BASE_URL="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_BRANCH}"

SUPPORT_ROOT="/Users/Shared/Savant/Library/Application Support/RacePointMedia"
TARGET_ROOT="${SENTINEL_TARGET_ROOT:-${SUPPORT_ROOT}/Sentinel}"
CUSTOMER_FILES_DIR="${SENTINEL_CUSTOMER_FILES_DIR:-${SUPPORT_ROOT}/userConfig.rpmConfig/CustomerFiles}"

BRIDGE_FILE="savant_network_sentinel_clean_rubi_bridge_v4_3b1_pro.rb"
MANUAL_FILE="manual_bridge_diagnose_v4_3b1_pro.sh"
PROBE_FILE="probe_sclibridge_v4_3b1_pro.sh"
COMPAT_FILE="rubi_compat_v4_3b1_pro.sh"
EXAMPLE_MANIFEST="example_harvest_manifest.txt"
BLUEPRINT_GEN="generate_harvest_manifest_from_blueprint.rb"
RPMCONFIG_GEN="generate_harvest_manifest_from_rpmconfig.rb"
PROCESS_MATCH_TOKEN="savant_network_sentinel_clean_rubi_bridge_"
START_COMMAND_CACHE_FILE="${TARGET_ROOT}/.sentinel_bridge_start_command.txt"
PID_FILE="${TARGET_ROOT}/sentinel_bridge.pid"
STOP_GRACE_SECONDS="${SENTINEL_STOP_GRACE_SECONDS:-3}"

RUNNING_BRIDGE_PIDS=()
RUNNING_BRIDGE_COMMANDS=()

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

pid_already_listed() {
  local pid="$1"
  local existing
  for existing in "${RUNNING_BRIDGE_PIDS[@]}"; do
    [[ "${existing}" == "${pid}" ]] && return 0
  done
  return 1
}

add_running_bridge_process() {
  local pid="$1"
  local command="$2"
  [[ -z "${pid}" ]] && return 0
  if pid_already_listed "${pid}"; then
    return 0
  fi
  RUNNING_BRIDGE_PIDS+=("${pid}")
  RUNNING_BRIDGE_COMMANDS+=("${command}")
}

discover_bridge_process_from_pid_file() {
  [[ -r "${PID_FILE}" ]] || return 1

  local pid command
  pid="$(head -n 1 "${PID_FILE}" 2>/dev/null | tr -d '[:space:]')"
  if [[ ! "${pid}" =~ ^[0-9]+$ ]]; then
    say "[warn] invalid bridge pid file content; removing: ${PID_FILE}"
    rm -f "${PID_FILE}" || true
    return 1
  fi

  if ! kill -0 "${pid}" >/dev/null 2>&1; then
    say "[warn] stale bridge pid file removed: ${PID_FILE}"
    rm -f "${PID_FILE}" || true
    return 1
  fi

  command="$(ps -p "${pid}" -o command= 2>/dev/null | head -n 1)"
  command="${command#"${command%%[![:space:]]*}"}"
  if [[ -n "${command}" && "${command}" != *"${PROCESS_MATCH_TOKEN}"* && "${command}" != *"${BRIDGE_FILE}"* ]]; then
    say "[warn] pid file points to unexpected process (${pid}); ignoring pid file."
    return 1
  fi

  add_running_bridge_process "${pid}" "${command}"
  say "[info] bridge pid file detected: ${PID_FILE} (pid ${pid})"
  return 0
}

discover_running_bridge_processes() {
  RUNNING_BRIDGE_PIDS=()
  RUNNING_BRIDGE_COMMANDS=()

  discover_bridge_process_from_pid_file || true

  local line trimmed pid command
  while IFS= read -r line; do
    trimmed="${line#"${line%%[![:space:]]*}"}"
    [[ -z "${trimmed}" ]] && continue

    pid="${trimmed%%[[:space:]]*}"
    command="${trimmed#"${pid}"}"
    command="${command#"${command%%[![:space:]]*}"}"

    [[ -z "${pid}" || -z "${command}" ]] && continue
    [[ "${command}" == *"${PROCESS_MATCH_TOKEN}"* ]] || continue
    [[ "${command}" == *"bridge_start"* ]] || continue

    add_running_bridge_process "${pid}" "${command}"
  done < <(ps -axww -o pid= -o command=)
}

choose_start_command() {
  local cmd
  for cmd in "${RUNNING_BRIDGE_COMMANDS[@]}"; do
    if [[ "${cmd}" == *"${TARGET_ROOT}/${BRIDGE_FILE}"* ]]; then
      printf '%s\n' "${cmd}"
      return 0
    fi
  done
  for cmd in "${RUNNING_BRIDGE_COMMANDS[@]}"; do
    if [[ "${cmd}" == *"${BRIDGE_FILE}"* ]]; then
      printf '%s\n' "${cmd}"
      return 0
    fi
  done
  if [[ ${#RUNNING_BRIDGE_COMMANDS[@]} -gt 0 ]]; then
    printf '%s\n' "${RUNNING_BRIDGE_COMMANDS[0]}"
    return 0
  fi
  return 1
}

persist_start_command() {
  local start_command="$1"
  [[ -z "${start_command}" ]] && return 0
  printf '%s\n' "${start_command}" > "${START_COMMAND_CACHE_FILE}"
  chmod 600 "${START_COMMAND_CACHE_FILE}"
  say "[ok] saved start command: ${START_COMMAND_CACHE_FILE}"
}

load_cached_start_command() {
  if [[ -r "${START_COMMAND_CACHE_FILE}" ]]; then
    head -n 1 "${START_COMMAND_CACHE_FILE}"
    return 0
  fi
  return 1
}

stop_running_bridge_processes() {
  if [[ ${#RUNNING_BRIDGE_PIDS[@]} -eq 0 ]]; then
    say "[info] no running bridge process found."
    return 0
  fi

  say "[info] stopping running bridge process(es): ${RUNNING_BRIDGE_PIDS[*]}"
  local pid
  for pid in "${RUNNING_BRIDGE_PIDS[@]}"; do
    kill "${pid}" >/dev/null 2>&1 || true
  done

  sleep "${STOP_GRACE_SECONDS}"

  local survivors=()
  for pid in "${RUNNING_BRIDGE_PIDS[@]}"; do
    if kill -0 "${pid}" >/dev/null 2>&1; then
      survivors+=("${pid}")
    fi
  done

  if [[ ${#survivors[@]} -gt 0 ]]; then
    say "[warn] force stopping bridge process(es): ${survivors[*]}"
    for pid in "${survivors[@]}"; do
      kill -9 "${pid}" >/dev/null 2>&1 || true
    done
    sleep 1
  fi

  rm -f "${PID_FILE}" || true
}

restart_bridge() {
  local start_command="$1"
  if [[ "${SENTINEL_SKIP_RESTART:-0}" == "1" ]]; then
    say "[info] restart skipped (SENTINEL_SKIP_RESTART=1)."
    return 0
  fi

  if [[ -z "${start_command}" ]]; then
    say "[warn] no saved bridge start command found; skipping automatic restart."
    say "[warn] restart manually by reloading the Blueprint profile or running your bridge_start command."
    return 0
  fi

  say "[info] restarting bridge with saved host config..."
  nohup bash -lc "${start_command}" >/dev/null 2>&1 &
  sleep 2

  local new_pid=""
  if [[ -r "${PID_FILE}" ]]; then
    new_pid="$(head -n 1 "${PID_FILE}" 2>/dev/null | tr -d '[:space:]')"
  fi
  if [[ "${new_pid}" =~ ^[0-9]+$ ]] && kill -0 "${new_pid}" >/dev/null 2>&1; then
    say "[ok] bridge restart command launched successfully (pid ${new_pid})."
  elif pgrep -f "${PROCESS_MATCH_TOKEN}" >/dev/null 2>&1; then
    say "[ok] bridge restart command launched successfully."
  else
    say "[warn] restart command executed, but bridge process is not visible yet."
  fi
}

main() {
  say "== Sentinel Savant Rubi Bridge (${VERSION}) update (ProHosts layout) =="
  say "Target root: ${TARGET_ROOT}"
  say

  mkdir -p "${TARGET_ROOT}" "${TARGET_ROOT}/logs"
  ensure_target_writable

  discover_running_bridge_processes
  local start_command=""
  if start_command="$(choose_start_command 2>/dev/null)"; then
    persist_start_command "${start_command}"
  elif start_command="$(load_cached_start_command 2>/dev/null)"; then
    say "[info] using previously saved start command."
  fi

  stop_running_bridge_processes

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

  say
  say "Bridge and companion files updated:"
  say "- ${TARGET_ROOT}/${BRIDGE_FILE}"
  say "- ${TARGET_ROOT}/${MANUAL_FILE}"
  say "- ${TARGET_ROOT}/${PROBE_FILE}"
  say "- ${TARGET_ROOT}/${COMPAT_FILE}"

  restart_bridge "${start_command}"
}

main "$@"
