# Sentinel Pro and Sentinel Savant Rubi Bridge
## Full Engineering and Security Whitepaper (v4.3b1-pro)

Date: 2026-04-01

## 1. Executive Summary

Sentinel is a homeowner-first monitoring and control-governance platform for
Savant systems. It is delivered as:

- Sentinel Pro App (iPhone, iPad, Apple TV)
- Sentinel Savant Rubi Bridge (Ruby runtime on the Savant host)

Sentinel is designed to provide high-value system visibility and controlled
actions while preserving homeowner authority over integrator access.

This v4.3b1-pro whitepaper defines the full concept, architecture, communication
protocols, cryptography profile, security posture, and homeowner-centric privacy
model.

## 2. Scope and Product Concept

Sentinel is intentionally more than a dashboard. It is an operational control
plane with explicit trust governance.

Primary goals:

1. Give homeowners clear, continuous visibility into system health.
2. Enable integrators to diagnose and support safely.
3. Enforce owner-controlled authorization and revocation.
4. Keep host overhead low for large deployments.
5. Preserve clear technical boundaries between telemetry and privileged actions.

Out of scope:

- Unbounded remote shell exposure to all users
- Full raw host data exfiltration
- Cloud dependency for core local monitoring operation

## 3. Architecture Overview

Sentinel uses a layered architecture:

1. Bridge layer (host-local Ruby service in Savant Rubi environment)
2. App layer (SwiftUI client across iOS/tvOS targets)
3. Persistent local Sentinel store (users, policy, audit, generated manifests)
4. Savant state and runtime sources (StateCenter via `sclibridge`, host runtime)

### 3.1 Data Plane

Savant StateCenter and runtime signals are harvested and normalized by the
bridge, then delivered to clients via curated JSON APIs.

Flow:

`StateCenter/readstate -> harvest engine -> normalized cache -> app UI`

### 3.2 Control Plane

Actions are gated through role policy, ACL checks, and action-specific safety
logic before host mutation is attempted.

Flow:

`app action -> authentication -> authorization + ACL -> guarded execution -> audit`

## 4. Bridge Design

Bridge runtime:

- File: `savant_network_sentinel_clean_rubi_bridge_v4_3b1_pro.rb`
- Runtime version constant: `4.3b1-pro`
- Ruby runtime model: WEBrick API service + harvest loop + local persistence

### 4.1 Network Service Model

- Bind host is configurable (`bind_host`), default `0.0.0.0`.
- Port is configurable (`app_port`), default `42042`.
- Bridge can run HTTP or HTTPS based on Blueprint/runtime config.

### 4.2 Harvesting and Scalability

- Discovers and resolves state candidates using controlled seed + manifest logic.
- Harvests with batched polling (`harvest_poll_seconds`) and cap (`harvest_max_states`).
- Supports generated and host-aware manifest strategies.
- Separates frequently changing telemetry from stable identity metadata.

### 4.3 Safety-Critical Command Handling

- Critical commands (for example host reboot) require explicit action payload and
  role authorization.
- Terminal sessions are time-bounded and auditable.
- Doorbell audio actions validate compatibility before replacing references.

### 4.4 Persistent State

Persistent files store:

- users and password hashes
- role and ACL permissions
- policy flags (pairing/authorization state)
- audit log (`sentinel_audit.jsonl`, retention window 90 days)
- generated bridge catalog and manifests

## 5. App Design

Sentinel Pro app is the user-facing control and monitoring surface:

- iPhone: compact operational controls and incident response
- iPad: denser multi-panel service visibility
- Apple TV: persistent home status board for shared visibility

### 5.1 UX Governance Features

- first-login password rotation flow
- role acknowledgment and monitoring acknowledgment gates
- integrator authorization by homeowner admin
- explicit owner controls for temporary disable and permanent integrator revoke

### 5.2 Operational Surfaces

- system dashboard and service rollups
- statecenter-driven status cards
- admin user/permission management (role dependent)
- audit activity views
- tools (terminal and controlled host actions)
- doorbell audio management workflow

## 6. Communication Protocols

## 6.1 Transport

- Local network or VPN path to bridge endpoint.
- Protocol: HTTP/1.1 JSON API over HTTP or HTTPS (WEBrick server).
- Default transport recommendation: HTTPS enabled.

## 6.2 API Style

- REST-like endpoint model
- UTF-8 JSON request/response
- Status-code based error handling with structured error payloads
- `Authorization: Bearer <token>` for authenticated endpoints

## 6.3 Endpoint Families

- Health and metadata:
  - `/`
  - `/health`
- Authentication and identity:
  - `/api/v1/auth/login`
  - `/api/v1/auth/me`
  - `/api/v1/auth/change-password`
- Pairing and acknowledgment:
  - `/api/v1/acknowledgements/monitoring`
  - `/api/v1/acknowledgements/role`
  - `/api/v1/pairing/authorize-integrator`
- Site data:
  - `/api/v1/site/config`
  - `/api/v1/site/status`
  - `/api/v1/site/discovery`
  - `/api/v1/site/host-runtime`
- Admin and audit:
  - `/api/v1/admin/users`
  - `/api/v1/admin/monitoring`
  - `/api/v1/audit`
  - `/api/v1/admin/audit`
- Tools:
  - terminal endpoints
  - reboot endpoint
  - doorbell endpoints

## 6.4 Session Protocol

- On successful login, bridge issues a random bearer token.
- Session includes role, expiry, and required-next-step flags.
- Session authorization is re-evaluated against policy and ACL state.
- Expired sessions are purged server-side.

## 7. Cryptography Profile

## 7.1 TLS and Bridge Identity

When HTTPS is enabled:

- Bridge generates or loads host-local X.509 certificate and key.
- Key type: RSA 2048-bit.
- Certificate signing digest: SHA-256.
- Fingerprint is computed as SHA-256 of DER certificate bytes and exposed by API.

## 7.2 App Trust Behavior

- App supports expected fingerprint comparison per home configuration.
- If fingerprint is configured, mismatch is rejected as bridge identity change.
- If fingerprint is not configured, TLS chain acceptance is less strict.

Operational implication:

- For production security, each home should store and enforce TLS fingerprint
  pinning in app configuration.

## 7.3 Password Storage

Bridge password handling:

- Algorithm: PBKDF2-HMAC-SHA256
- New-password iteration count: 210,000
- Legacy compatibility iteration count: 20,000
- Per-user random salt (`SecureRandom.hex(16)`)
- Hash output stored instead of plaintext

## 7.4 Session Secrets

- Session tokens are generated with `SecureRandom.hex(24)`.
- Tokens are kept in bridge memory and are not intended for long-term storage.

## 8. Security Architecture

## 8.1 Role Model

Primary roles:

- `integrator`
- `home_admin`
- `home_user`

Key constraints:

- singleton integrator and singleton home admin roles
- homeowner-centric authority for integrator authorization
- homeowner controls for temporary disable and permanent revoke

## 8.2 ACL Model

Permissions are normalized across:

- services
- devices
- states
- actions

This enables least-privilege filtering for both data visibility and action
eligibility.

## 8.3 Governance Gates

- mandatory password change gates
- monitoring and role acknowledgment gates
- pairing completion requirements
- action-level checks before mutating host behavior

## 8.4 Audit and Accountability

- Security and admin events are logged as JSONL entries.
- Retention policy: 90 days (pruning applied by bridge).
- Audit surfaces are role-filtered in API and app UI.

## 9. Homeowner-Centric Privacy Design

Sentinel privacy design is based on five principles:

1. Owner authority
2. Explicit consent and acknowledgment
3. Data minimization
4. Locality by default
5. Transparent accountability

## 9.1 Data Minimization

- Bridge serves curated telemetry, not unrestricted host internals.
- Access to state namespaces is filtered by ACL and role.
- Sensitive text is masked/redacted in operational views where practical.

## 9.2 Locality and Data Residency

- Core monitoring data path is local to host and app over LAN/VPN.
- User store and audit logs are host-local files.
- No mandatory cloud dependency for core bridge telemetry path.

## 9.3 Consent and Revocability

- Homeowner acknowledgment and authorization are first-class gates.
- Integrator access can be temporarily disabled or permanently revoked.
- Revocation is durable in policy and reflected in session behavior.

## 9.4 What Is Not Claimed

To avoid ambiguity:

- The current baseline does not claim full encrypted-at-rest stores for all
  Sentinel files.
- TLS pinning is available but depends on operator configuration in the app.

## 10. Threat Model and Residual Risk

## 10.1 Addressed Threats

- credential disclosure in transit (mitigated by HTTPS)
- weak password persistence (mitigated by PBKDF2 + policy + forced rotation)
- unauthorized endpoint access (mitigated by bearer auth + role + ACL checks)
- silent support access (mitigated by homeowner authorization and audit trails)

## 10.2 Residual Risks

- self-signed certificate trust must be operationally managed
- unpinned TLS mode weakens identity binding
- compromised trusted client can still misuse valid tokens until expiry
- host filesystem permissions remain important for local file confidentiality

## 11. Security Hardening Roadmap

Recommended near-term enhancements:

1. Enforce HTTPS + fingerprint pinning by default for new homes.
2. Add explicit in-app fingerprint onboarding and rotation workflow.
3. Shorten privileged session lifetime and add finer-grained re-auth controls.
4. Add stronger mutation replay protections for critical commands.
5. Expand endpoint-level rate limits and lockout telemetry.
6. Add optional encrypted-at-rest storage for sensitive Sentinel files.

## 12. Verification and Testing Framework

Minimum release verification should include:

- unit tests for auth, ACL, and password policy behavior
- API contract validation for success/error schemas
- TLS and fingerprint mismatch simulation tests
- harvest performance checks on high-state-count homes
- audit log generation and retention-prune verification
- permission boundary tests for integrator/home_admin/home_user roles

## 13. Conclusion

Sentinel is engineered as a secure, homeowner-governed operational platform for
Savant estates. Its design combines:

- practical host-compatible bridge architecture
- role- and ACL-aware app experiences
- explicit governance and revocation controls
- modern cryptographic primitives for credentials and transport
- privacy-centric data minimization and local-first operations

This framework allows Sentinel to scale feature depth while preserving trust,
safety, and owner control.
