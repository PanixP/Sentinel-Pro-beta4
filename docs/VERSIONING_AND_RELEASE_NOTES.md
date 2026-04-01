# Sentinel Platform

> Copyright (c) Savant Cyprus 2026
>
> Bridge & App microsite link: [Savant Sentinel Pro](https://savantcyprus.com/sentinel-pro.html)

## Versioning and Release Notes

This file tracks bridge and blueprint release lines for this repository.

## Bridge Versioning Model

- Major: protocol or deployment model changes (`v3.x`, `v4.x`)
- Minor: feature additions and non-breaking API/installer updates
- Patch: stability, parser, and installer fixes

Bridge runtime file:

- `savant_network_sentinel_clean_rubi_bridge_v4_3b1_pro.rb`

Bridge XML alias line:

- `SmartHost Sentinel Rubi Bridge v4.3b1-pro`
- `ProHost Sentinel Rubi Bridge v4.3b1-pro`

## Current Baselines

- Bridge runtime: `v4.3b1-pro`
- Bridge XML defaults: `harvest_max_states = 7000`

## Release Notes

## 4.3b1-pro (beta4 migration + freeze) — 2026-04-01

- Migrated bridge/blueprint bundle into new repository:
  - `https://github.com/PanixP/Sentinel-Pro-beta4`
- Bumped runtime/build naming to `v4.3b1-pro`:
  - `savant_network_sentinel_clean_rubi_bridge_v4_3b1_pro.rb`
  - `manual_bridge_diagnose_v4_3b1_pro.sh`
  - `probe_sclibridge_v4_3b1_pro.sh`
  - `rubi_compat_v4_3b1_pro.sh`
- Updated internal runtime version and log naming:
  - API version now reports `4.3b1-pro`
  - log file now defaults to `savant_network_sentinel_clean_rubi_bridge_v4_3b1_pro.log`
- SmartHosts default bridge root changed to:
  - `/home/RPM/Sentinel`
- Updated wrapper and installer defaults to pull from:
  - `PanixP/Sentinel-Pro-beta4`
- Documentation refresh:
  - `docs/BETA_TESTER_READINESS_v4.3b1-pro.md`
  - `docs/Sentinel-Pro-Engineering-Whitepaper-v4.3b1-pro.md`
  - updated installation and curl command references

## 4.2.0 (documentation baseline)

- Published full engineering and security whitepaper covering:
  - app and bridge concept
  - architecture and design model
  - communication protocols
  - cryptography profile
  - homeowner-centric privacy design
  - threat model and hardening roadmap
- New canonical whitepaper:
  - `docs/Sentinel-Pro-Engineering-Whitepaper-v4.2.md`
- Retained legacy markdown alias for backward compatibility:
  - `docs/Sentinel-Engineering-Whitepaper.md`

## 4.1.1 (bridge line)

- Blueprint profile filenames normalized to:
  - `Panix_Sentinel Pro Pro Host.xml`
  - `Panix_Sentinel Pro Smart Host.xml`
- Icon filenames normalized to:
  - `Panix_Sentinel Pro Pro Host.icns`
  - `Panix_Sentinel Pro Smart Host.icns`
- XML validation script updated for normalized filenames.
- Documentation/curl guides synchronized with repo structure.
- Doorbell operator runbook published:
  - `docs/DOORBELL_AUDIO_OPERATOR_WORKFLOW.md`

## 4.0.x (bridge governance/security line)

- Added homeowner temporary integrator-access control endpoint.
- Added login blocking reason: `integrator_access_temporarily_disabled`.
- Added related pairing/session payload and audit events.
- Kept permanent revoke flow via `POST /api/v1/home/revoke-integrator`.

## Upgrade Notes (Bridge)

ProHosts update:

```bash
curl -fsSL https://raw.githubusercontent.com/PanixP/Sentinel-Pro-beta4/main/update_sentinel_bridge_ProHosts.sh | bash
```

SmartHosts update:

```bash
curl -fsSL https://raw.githubusercontent.com/PanixP/Sentinel-Pro-beta4/main/update_sentinel_bridge_SmartHosts.sh | bash
```
