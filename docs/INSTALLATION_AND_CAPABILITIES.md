# Sentinel Savant Rubi Bridge
## Installation, Capabilities, and Profile/Script Differences

This guide covers the complete deployment model for the Sentinel bridge bundle
using the renamed host families:

- `ProHosts` = modern shared-user SavantOS hosts
- `SmartHosts` = older GNUstep/RPM-layout hosts

## Capability Summary

- Secure app-facing bridge API over HTTPS
- Stateful ACL-aware user/session handling
- Live state discovery with rotating `readstate` harvest
- Batched state polling tuned for larger homes
- Runtime diagnostics exposed to StateCenter
- Terminal tool endpoints for app-initiated host diagnostics
- Guard-railed reboot endpoint requiring explicit confirmations
- Doorbell audio management endpoints with WAV compatibility validation
- Dual-host filesystem compatibility model via separate scripts and XML profiles

## Bundle Inventory

- Bridge runtime:
  - `savant_network_sentinel_clean_rubi_bridge_v4_3b1_pro.rb`
- Profiles:
  - `Panix_Sentinel Pro Pro Host.xml`
  - `Panix_Sentinel Pro Smart Host.xml`
- Icons:
  - `Panix_Sentinel Pro Pro Host.icns`
  - `Panix_Sentinel Pro Smart Host.icns`
- Install scripts:
  - `install_sentinel_dependencies_ProHosts.sh`
  - `install_sentinel_dependencies_SmartHosts.sh`
- Update scripts:
  - `update_sentinel_bridge_ProHosts.sh`
  - `update_sentinel_bridge_SmartHosts.sh`
- Script internals:
  - `scripts/install_first_time_ProHosts.sh`
  - `scripts/install_first_time_SmartHosts.sh`
  - `scripts/update_bridge_ProHosts.sh`
  - `scripts/update_bridge_SmartHosts.sh`

## XML Profile Identity

### SmartHost profile

- Filename: `Panix_Sentinel Pro Smart Host.xml`
- Manufacturer: `Panix`
- Model: `Sentinel Pro Smart Host`
- Alias: `SmartHost Sentinel Rubi Bridge v4.3b1-pro`

### ProHost profile

- Filename: `Panix_Sentinel Pro Pro Host.xml`
- Manufacturer: `Panix`
- Model: `Sentinel Pro Pro Host`
- Alias: `ProHost Sentinel Rubi Bridge v4.3b1-pro`

## Script Differences: ProHosts vs SmartHosts

### `ProHosts` scripts

Use these on modern SavantOS hosts where Sentinel runtime files should live under:

- `/Users/Shared/Savant/Library/Application Support/RacePointMedia/Sentinel`

First-install ProHosts script behavior:

- installs `benumc/rubi.sh`
- installs bridge/runtime companion files
- creates/repairs compatibility symlinks:
  - `/Users/RPM/Applications/RacePointMedia -> /Users/Shared/Savant/Applications/RacePointMedia`
  - `/Users/RPM/Library/Application Support/RacePointMedia -> /Users/Shared/Savant/Library/Application Support/RacePointMedia`
- avoids replacing non-empty real directories

### `SmartHosts` scripts

Use these on older RPM-layout hosts where Sentinel runtime files should live under:

- `/home/RPM/Sentinel`

First-install SmartHosts script behavior:

- installs `benumc/rubi.sh`
- installs bridge/runtime companion files
- does not manage ProHost compatibility symlinks

### Update scripts

Update scripts are host-family specific and refresh bridge/runtime files only.
They do not reset user stores by default and do not alter host family root paths.

## XML Differences: ProHost vs SmartHost

Both XML profiles share the same command model and dynamic status bindings, but
they differ in default path states:

- `local_script_path`
- `tls_cert_file`
- `tls_key_file`
- `log_directory`
- `users_file`

`ProHost` XML points to `/Users/Shared/Savant/Library/Application Support/...`.
`SmartHost` XML points to `/home/RPM/Sentinel/...`.

Both profiles default to:

- `script_file = savant_network_sentinel_clean_rubi_bridge_v4_3b1_pro.rb`
- `harvest_max_states = 7000`

## Installation Guidance

## GitHub curl-first installer commands

Repository:

- `https://github.com/PanixP/Sentinel-Pro-beta4`
- branch: `main`

First-time ProHosts install:

```bash
curl -fsSL https://raw.githubusercontent.com/PanixP/Sentinel-Pro-beta4/main/install_sentinel_dependencies_ProHosts.sh | bash
```

First-time SmartHosts install:

```bash
curl -fsSL https://raw.githubusercontent.com/PanixP/Sentinel-Pro-beta4/main/install_sentinel_dependencies_SmartHosts.sh | bash
```

Bridge update ProHosts:

```bash
curl -fsSL https://raw.githubusercontent.com/PanixP/Sentinel-Pro-beta4/main/update_sentinel_bridge_ProHosts.sh | bash
```

Bridge update SmartHosts:

```bash
curl -fsSL https://raw.githubusercontent.com/PanixP/Sentinel-Pro-beta4/main/update_sentinel_bridge_SmartHosts.sh | bash
```

### 1) Select host family

- If host is modern shared-user layout: use `ProHosts`.
- If host is older RPM layout: use `SmartHosts`.

### 2) Run first-time dependency install

ProHosts:

```bash
bash install_sentinel_dependencies_ProHosts.sh
```

SmartHosts:

```bash
bash install_sentinel_dependencies_SmartHosts.sh
```

### 3) Import matching XML in Blueprint

- ProHosts host: import `Panix_Sentinel Pro Pro Host.xml`
- SmartHosts host: import `Panix_Sentinel Pro Smart Host.xml`

### 4) Confirm key XML states

- `local_script_path` matches installed host family path
- `script_file` is `savant_network_sentinel_clean_rubi_bridge_v4_3b1_pro.rb`
- `harvest_max_states` set to desired cap (default `7000`)

### 5) Use update scripts for bridge refreshes

ProHosts:

```bash
bash update_sentinel_bridge_ProHosts.sh
```

SmartHosts:

```bash
bash update_sentinel_bridge_SmartHosts.sh
```

## Schema Compliance and Filename Checks

- XML filenames use schema-safe Panix naming conventions.
- Profile metadata is set explicitly in `<component ...>` attributes.
- Validate both XML files with:

```bash
./scripts/validate_xml.sh
```

The validation script checks both profile files against:

- `docs/racepoint_component_profile.xsd`

## Operational Notes

- Avoid mixing host family scripts and XML files.
- Keep profile and script host family aligned to prevent path regressions.
- Use first-install scripts only for first deployment or full environment repair.
- Use update scripts for normal bridge version refreshes.
- Doorbell audio operations and troubleshooting are documented in:
  - `docs/DOORBELL_AUDIO_OPERATOR_WORKFLOW.md`

## Homeowner-centric access controls

- Homeowner can permanently revoke installer/integrator access.
- Homeowner can temporarily disable and later re-enable integrator access.
- Temporary disable closes active integrator sessions immediately.
- Permanent revoke still requires a new Blueprint config revision/reset flow.
