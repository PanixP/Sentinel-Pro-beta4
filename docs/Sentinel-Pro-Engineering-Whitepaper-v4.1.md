# Sentinel Pro and Sentinel Savant Rubi Bridge

> Copyright (c) Savant Cyprus 2026
>
> Bridge & App microsite link: [Savant Sentinel Pro](https://savantcyprus.com/sentinel-pro.html)

## Engineering Whitepaper (v4.1)

Date: 2026-03-30

## 1. Introduction

Sentinel Pro is a homeowner-first operational intelligence platform for Savant
homes. The platform combines:

- Sentinel Pro App (iPhone, iPad, Apple TV)
- Sentinel Savant Rubi Bridge (host-resident bridge runtime)

The bridge securely exposes curated operational telemetry and controlled actions
from the Savant host, while the app provides role-aware monitoring, diagnostics,
pairing workflows, and administrative controls.

## 2. Concept and Product Positioning

Sentinel Pro is designed as a production-safe visibility and governance layer
for Savant installations.

Core concept:

- Preserve homeowner authority while enabling integrator support.
- Provide transparent diagnostics without unsafe host-level access.
- Keep host overhead low for large systems with high state counts.
- Adapt to project-specific naming and schema patterns across different homes.

## 3. Target Market and User Base

Primary users:

- Homeowners requiring live confidence, accountability, and access control.
- Integrators and service teams requiring efficient remote diagnostics.
- Managed residential estates and premium multi-zone installations.

Secondary users:

- Project managers and commissioning teams validating lifecycle health.
- Technical support teams handling post-handover service.

## 4. Architecture

Sentinel is structured as three cooperating layers:

1. Host bridge layer (Ruby runtime in Savant rubi environment)
2. App layer (SwiftUI for iPhone/iPad/tvOS)
3. Persistent Sentinel store and audit state on host filesystem

Data flow:

Savant host states -> bridge harvest/discovery -> normalized payloads -> app UI.

Control flow:

App authenticated action -> bridge ACL/policy checks -> controlled host action.

## 5. Security and Privacy Safeguards (Homeowner-Centric)

Sentinel is intentionally designed so homeowner authority is explicit and
enforceable.

Safeguards include:

- Mandatory first-login password rotation for temporary accounts.
- Role and monitoring acknowledgements in pairing workflows.
- Homeowner authorization required for integrator access.
- Homeowner temporary disable and permanent revoke capabilities.
- Session-scoped access with role + ACL filtering.
- Audit logging for security-sensitive events and administrative actions.

Privacy posture:

- Data exposure is bounded to approved monitoring surfaces.
- Bridge returns curated telemetry rather than unrestricted host internals.
- Credentials are stored with hashed password material, not plaintext.

## 6. Protocols and Algorithms

Transport and network:

- HTTPS app-to-bridge transport
- Bridge certificate/key material stored on host
- TLS fingerprint pinning (app trust-on-first-use model)
- JSON API over HTTP(S) endpoints

Authentication and authorization:

- Bearer-token session model
- Role-based access control
- ACL gate checks on sensitive endpoints

Credential handling:

- PBKDF2-SHA256 password hashing with salt and per-user metadata
- Password policy checks against weak patterns and constrained inputs

State acquisition and performance:

- `sclibridge statenames` discovery for available states
- Batched `sclibridge readstate` harvest strategy
- Manifest-based prioritization for large homes
- Caching of stable identity/runtime fields where appropriate

Operational safety:

- Guard-railed critical actions (confirmation-driven flow)
- Persistent audit trail for pairing, access changes, and admin operations

## 7. Host Layout Compatibility

The bridge supports two Savant host families:

- ProHosts:
  - `/Users/Shared/Savant/.../Application Support/...`
- SmartHosts:
  - `/home/RPM/GNUstep/.../ApplicationSupport/...`
  - runtime defaults under `/home/RPM/Sentinel`

Installer and updater scripts are split by host family to avoid path regressions.

## 8. Blueprint and Profile Compliance

Blueprint profile deliverables:

- `Panix_Sentinel Pro Pro Host.xml`
- `Panix_Sentinel Pro Smart Host.xml`
- `Panix_Sentinel Pro Pro Host.icns`
- `Panix_Sentinel Pro Smart Host.icns`

Validation:

- XML profiles are schema-checked with
  `docs/racepoint_component_profile.xsd`.

## 9. Engineering Priorities for Scale

For large homes and high mirrored-state counts:

- Keep payloads incremental and cache-friendly.
- Avoid expensive full refresh logic on every UI update.
- Use batched state processing and scoped parsing pipelines.
- Separate stable identity data from live telemetry streams.
- Keep UI rendering virtualized and model updates throttled.

## 10. Conclusion

Sentinel Pro and Sentinel Savant Rubi Bridge provide a practical and secure
operational framework for Savant environments where homeowner trust,
integrator serviceability, and production stability must coexist.

The platform is engineered to remain adaptable across diverse projects while
preserving strict control boundaries and transparent security behavior.
