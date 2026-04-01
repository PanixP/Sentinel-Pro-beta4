#!/bin/zsh
set -u

if [[ -d "/home/RPM/Sentinel" ]]; then
  DEFAULT_SENTINEL_ROOT="/home/RPM/Sentinel"
else
  DEFAULT_SENTINEL_ROOT="/Users/Shared/Savant/Library/Application Support/RacePointMedia/Sentinel"
fi

SCRIPT_PATH="${1:-${DEFAULT_SENTINEL_ROOT}/savant_network_sentinel_clean_rubi_bridge_v4_3b1_pro.rb}"
BIND_HOST="${2:-0.0.0.0}"
APP_PORT="${3:-42042}"
USE_HTTPS="${4:-1}"
TLS_CERT_FILE="${5:-${DEFAULT_SENTINEL_ROOT}/sentinel_bridge.crt}"
TLS_KEY_FILE="${6:-${DEFAULT_SENTINEL_ROOT}/sentinel_bridge.key}"
LOG_DIRECTORY="${7:-${DEFAULT_SENTINEL_ROOT}/logs/}"
LOG_LEVEL="${8:-INFO}"
USERS_FILE="${9:-${DEFAULT_SENTINEL_ROOT}/sentinel_users.json}"
BOOTSTRAP_USERNAME="${10:-installer}"
BOOTSTRAP_PASSWORD="${11:-change_me_now}"
BOOTSTRAP_CONFIG_REVISION="${12:-v1}"
INTEGRATOR_RESET_FLAG="${13:-0}"
HARVEST_STATE_LIST="${14:-}"
HARVEST_POLL_SECONDS="${15:-15}"
HARVEST_MODE="${16:-hybrid}"
HARVEST_MANIFEST_FILE="${17:-auto}"
HARVEST_MAX_STATES="${18:-7000}"

print_section() {
  echo
  echo "== $1 =="
}

show_path() {
  local label="$1"
  local path="$2"
  if [[ -e "$path" ]]; then
    echo "[OK] $label: $path"
  else
    echo "[MISS] $label: $path"
  fi
}

print_section "Sentinel Manual Bridge Diagnose v4.3b1-pro"
echo "Script path: $SCRIPT_PATH"
echo "Bind host:   $BIND_HOST"
echo "App port:    $APP_PORT"
echo "HTTPS:       $USE_HTTPS"
echo "Users file:  $USERS_FILE"
echo "Manifest:    $HARVEST_MANIFEST_FILE"

print_section "Platform"
sw_vers 2>/dev/null || true
echo "Ruby: $(ruby -v 2>/dev/null || echo unavailable)"
echo "User: $(whoami 2>/dev/null || echo unknown)"
echo "PWD:  $(pwd)"

print_section "Expected Paths"
show_path "Bridge Ruby" "$SCRIPT_PATH"
show_path "Shared RacePointMedia" "/Users/Shared/Savant/Applications/RacePointMedia"
show_path "Shared Application Support" "/Users/Shared/Savant/Library/Application Support/RacePointMedia"
show_path "Legacy RPM app path" "/Users/RPM/Applications/RacePointMedia"
show_path "Legacy RPM support path" "/Users/RPM/Library/Application Support/RacePointMedia"
show_path "Legacy GNUstep support path" "/home/RPM/GNUstep/Library/ApplicationSupport/RacePointMedia"
show_path "SmartHosts writable Sentinel path" "/home/RPM/Sentinel"

print_section "sclibridge"
for candidate in \
  "/Users/Shared/Savant/Applications/RacePointMedia/sclibridge" \
  "/Users/RPM/Applications/RacePointMedia/sclibridge" \
  "/home/RPM/Applications/RacePointMedia/sclibridge" \
  "/usr/local/bin/sclibridge"
do
  if [[ -x "$candidate" ]]; then
    echo "[OK] executable: $candidate"
  elif [[ -e "$candidate" ]]; then
    echo "[WARN] exists but not executable: $candidate"
  else
    echo "[MISS] $candidate"
  fi
done

print_section "Ruby Syntax"
ruby -c "$SCRIPT_PATH"
syntax_status=$?
if [[ $syntax_status -ne 0 ]]; then
  echo
  echo "Bridge Ruby syntax failed. Stop here and fix the script before trying Rubi."
  exit $syntax_status
fi

print_section "Writable Directories"
mkdir -p "$LOG_DIRECTORY" "$(dirname "$USERS_FILE")" 2>/dev/null
if [[ -d "$LOG_DIRECTORY" ]]; then
  echo "[OK] log directory ready: $LOG_DIRECTORY"
else
  echo "[FAIL] log directory not writable: $LOG_DIRECTORY"
fi
if [[ -d "$(dirname "$USERS_FILE")" ]]; then
  echo "[OK] store directory ready: $(dirname "$USERS_FILE")"
else
  echo "[FAIL] store directory not writable: $(dirname "$USERS_FILE")"
fi

print_section "Manual Ruby Load Test"
ruby -e "load '$SCRIPT_PATH'; puts 'LOAD_OK'" 2>&1
load_status=$?
if [[ $load_status -ne 0 ]]; then
  echo
  echo "The script cannot even be loaded directly by Ruby. This usually means a wrong path or a runtime dependency problem."
  exit $load_status
fi

print_section "Manual Bridge Start"
echo "This keeps the process attached in the foreground."
echo "Press Ctrl+C after you see sentinel_api/statecenter_harvest output or after testing /health."
echo
ruby -e "load '$SCRIPT_PATH'; savant_network_sentinel_dispatch('bridge_start,$BIND_HOST,$APP_PORT,$USE_HTTPS,$TLS_CERT_FILE,$TLS_KEY_FILE,$LOG_DIRECTORY,$LOG_LEVEL,$USERS_FILE,$BOOTSTRAP_USERNAME,$BOOTSTRAP_PASSWORD,$BOOTSTRAP_CONFIG_REVISION,$INTEGRATOR_RESET_FLAG,$HARVEST_STATE_LIST,$HARVEST_POLL_SECONDS,$HARVEST_MODE,$HARVEST_MANIFEST_FILE,$HARVEST_MAX_STATES'); sleep"
