#!/bin/bash
set -u

TIMEOUT_SECONDS="${SENTINEL_PROBE_TIMEOUT:-5}"

print_section() {
  printf '\n== %s ==\n' "$1"
}

detect_sclibridge() {
  local candidates=(
    "/Users/Shared/Savant/Applications/RacePointMedia/sclibridge"
    "/Users/RPM/Applications/RacePointMedia/sclibridge"
    "/home/RPM/Applications/RacePointMedia/sclibridge"
    "/usr/local/bin/sclibridge"
    "sclibridge"
  )

  local candidate
  for candidate in "${candidates[@]}"; do
    if [[ "$candidate" == "sclibridge" ]]; then
      if command -v sclibridge >/dev/null 2>&1; then
        command -v sclibridge
        return 0
      fi
    elif [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

run_probe() {
  local label="$1"
  shift

  print_section "$label"
  printf 'Command:'
  printf ' %q' "$@"
  printf '\n'

  local output
  local status
  output="$(python3 - "$TIMEOUT_SECONDS" "$@" 2>&1 <<'PY'
import subprocess
import sys

timeout = int(sys.argv[1])
cmd = sys.argv[2:]

try:
    completed = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    sys.stdout.write(completed.stdout)
    sys.stderr.write(completed.stderr)
    sys.exit(completed.returncode)
except subprocess.TimeoutExpired as exc:
    if exc.stdout:
        sys.stdout.write(exc.stdout)
    if exc.stderr:
        sys.stderr.write(exc.stderr)
    print(f"[timeout after {timeout}s]")
    sys.exit(124)
PY
)"
  status=$?

  printf 'Exit: %s\n' "$status"
  if [[ -n "$output" ]]; then
    printf '%s\n' "$output"
  else
    printf '[no output]\n'
  fi
}

main() {
  print_section "Sentinel sclibridge Probe v4.3b1-pro"
  sw_vers 2>/dev/null || true
  printf 'User: %s\n' "$(whoami 2>/dev/null || echo unknown)"
  printf 'PWD:  %s\n' "$(pwd)"

  local sclibridge
  if ! sclibridge="$(detect_sclibridge)"; then
    printf '\n[FAIL] Unable to find sclibridge in known paths or PATH.\n'
    exit 1
  fi

  printf 'sclibridge: %s\n' "$sclibridge"

  print_section "Binary Strings Hint"
  if command -v strings >/dev/null 2>&1; then
    strings "$sclibridge" 2>/dev/null | grep -Ei 'state|trigger|list|dump|read' | head -n 50 || true
  else
    echo "strings not available"
  fi

  run_probe "No Args" "$sclibridge"
  run_probe "Help Verb" "$sclibridge" help
  run_probe "Short Help" "$sclibridge" -h
  run_probe "Long Help" "$sclibridge" --help

  run_probe "Read CurrentMinute" "$sclibridge" readstate global.CurrentMinute
  run_probe "Read rubi" "$sclibridge" readstate global.rubi
  run_probe "Read SystemStatus" "$sclibridge" readstate global.SystemStatus
  run_probe "List User Zones" "$sclibridge" userzones
  run_probe "State Names" "$sclibridge" statenames
  run_probe "State Names Filter global" "$sclibridge" statenames global

  run_probe "Candidate liststates" "$sclibridge" liststates
  run_probe "Candidate liststate" "$sclibridge" liststate
  run_probe "Candidate dumpstate" "$sclibridge" dumpstate
  run_probe "Candidate dumpstates" "$sclibridge" dumpstates
  run_probe "Candidate readstates" "$sclibridge" readstates
  run_probe "Candidate listtriggers" "$sclibridge" listtriggers
  run_probe "Candidate triggerhelp" "$sclibridge" help trigger
}

main "$@"
