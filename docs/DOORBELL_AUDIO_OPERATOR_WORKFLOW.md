# Doorbell Audio Operator Workflow

This guide documents the recommended operational flow for managing Savant
doorbell audio through Sentinel Pro.

## Scope

- Bridge branch: `codex/sentinel-rubi-bridge-v4-pro`
- Runtime: `savant_network_sentinel_clean_rubi_bridge_v4_3b1_pro.rb`
- App branch expected: `codex/sentinel-pro-baseline`

## Supported Endpoints

- `GET /api/v1/tools/doorbell/status`
- `GET /api/v1/tools/doorbell/sample-audio?sample_id=...`
- `POST /api/v1/tools/doorbell/apply-sample`
- `POST /api/v1/tools/doorbell/upload`

## Operator Flow

1. Open Sentinel Pro and connect to the target home.
2. Open `Tools` and launch `Doorbell Audio`.
3. Press `Refresh` to read the active reference path and expected WAV format.
4. Preview bundled samples with `Play`.
5. Apply a bundled sound with `Apply`, or upload a custom WAV.
6. If required by the host, provide sudo password before applying changes.
7. Confirm the bridge response and check whether service reload succeeded.
8. If reload is unavailable, follow the soft reboot recommendation.

## Custom WAV Rules

Custom WAV files must match the active Savant reference for:

- codec / audio format
- channel count
- sample rate
- bit depth
- frame duration

If any field differs, the bridge returns `doorbell_audio_mismatch` with
explicit mismatch details.

## Typical Errors and Meaning

- `invalid_wav_file`: uploaded file is not a supported WAV payload.
- `doorbell_reference_not_found`: active config has no valid doorbell reference.
- `sudo_password_required`: host patch path requires elevated privileges.
- `sample_not_found`: requested sample id does not exist.
- `sample_file_missing`: sample metadata exists but file is absent on host.
- `sample_preview_exception`: sample audio could not be streamed for preview.

## Validation Checklist

- Verify `/api/v1/tools/doorbell/status` returns `reference_audio`.
- Verify at least one `sample_sounds` entry is `available: true`.
- Confirm sample preview audio can be fetched from `sample-audio`.
- Apply one bundled sample and confirm a successful response.
- Upload one known-good WAV and verify no compatibility mismatches.
