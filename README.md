# Sentinel Pro Beta4 Bridge Bundle

Bridge and Blueprint release repository for Sentinel Rubi bridge build `v4.3b1-pro`.

## Included Files

- Bridge runtime: `savant_network_sentinel_clean_rubi_bridge_v4_3b1_pro.rb`
- Blueprint profiles:
  - `Panix_Sentinel Pro Pro Host.xml`
  - `Panix_Sentinel Pro Smart Host.xml`
- Install/update wrappers:
  - `install_sentinel_dependencies_ProHosts.sh`
  - `install_sentinel_dependencies_SmartHosts.sh`
  - `update_sentinel_bridge_ProHosts.sh`
  - `update_sentinel_bridge_SmartHosts.sh`
- Script payloads: `scripts/`
- Release docs: `docs/`

SmartHosts default bridge root is now:

- `/home/RPM/Sentinel`

## Quick Install / Update (main branch)

First-time ProHosts:

```bash
curl -fsSL https://raw.githubusercontent.com/PanixP/Sentinel-Pro-beta4/main/install_sentinel_dependencies_ProHosts.sh | bash
```

First-time SmartHosts:

```bash
curl -fsSL https://raw.githubusercontent.com/PanixP/Sentinel-Pro-beta4/main/install_sentinel_dependencies_SmartHosts.sh | bash
```

Update ProHosts:

```bash
curl -fsSL https://raw.githubusercontent.com/PanixP/Sentinel-Pro-beta4/main/update_sentinel_bridge_ProHosts.sh | bash
```

Update SmartHosts:

```bash
curl -fsSL https://raw.githubusercontent.com/PanixP/Sentinel-Pro-beta4/main/update_sentinel_bridge_SmartHosts.sh | bash
```

## Documentation

- `docs/INSTALLATION_AND_CAPABILITIES.md`
- `docs/VERSIONING_AND_RELEASE_NOTES.md`
- `docs/BETA_TESTER_READINESS_v4.3b1-pro.md`
- `docs/Sentinel-Pro-Engineering-Whitepaper-v4.3b1-pro.md`

## License

MIT (see `LICENSE`).
