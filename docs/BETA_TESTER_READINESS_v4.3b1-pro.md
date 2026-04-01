# Sentinel Pro Beta Readiness v4.3b1-pro

This checklist is the release-handoff pack for beta testers.

## Scope

- Bridge runtime: `v4.3b1-pro`
- Branch source: `main`
- Freeze date: `2026-04-01`

## What Is Included

- Latest bridge runtime + install/update scripts from `main`
- Updated ProHost and SmartHost blueprint XMLs
- SmartHosts default runtime root changed to `/home/RPM/Sentinel`
- Updated documentation and version notes

## Tester Pull Instructions

```bash
git clone https://github.com/PanixP/Sentinel-Pro-beta4.git
cd Sentinel-Pro-beta4
git checkout main
git pull
```

## Bridge Update Commands

ProHosts:

```bash
curl -fsSL https://raw.githubusercontent.com/PanixP/Sentinel-Pro-beta4/main/update_sentinel_bridge_ProHosts.sh | bash
```

SmartHosts:

```bash
curl -fsSL https://raw.githubusercontent.com/PanixP/Sentinel-Pro-beta4/main/update_sentinel_bridge_SmartHosts.sh | bash
```

## Verify Bridge Runtime

```bash
curl -k https://<HOST_IP>:42042/health
```

Expected in response:

- `"version": "4.3b1-pro"`
- `"status": "ok"`

## Known Environment Notes

- If host has HTTPS bridge enabled, use `https://` in app and curl checks.
- SmartHosts runtime files now default under `/home/RPM/Sentinel`.
