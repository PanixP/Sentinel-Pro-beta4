#!/bin/bash
set -euo pipefail

REPO_OWNER="${SENTINEL_REPO_OWNER:-PanixP}"
REPO_NAME="${SENTINEL_REPO_NAME:-Sentinel-Pro-beta4}"
REPO_BRANCH="${SENTINEL_REPO_BRANCH:-main}"
RAW_BASE_URL="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_BRANCH}"
REMOTE_SCRIPT_PATH="scripts/update_bridge_SmartHosts.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)"
LOCAL_SCRIPT="${SCRIPT_DIR}/${REMOTE_SCRIPT_PATH}"
if [[ -n "${SCRIPT_DIR}" && -r "${LOCAL_SCRIPT}" ]]; then
  exec bash "${LOCAL_SCRIPT}" "$@"
fi

REMOTE_URL="${RAW_BASE_URL}/${REMOTE_SCRIPT_PATH}"
curl -fsSL "${REMOTE_URL}" | bash -s -- "$@"
