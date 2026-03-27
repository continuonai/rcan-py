# Changelog

All notable changes to rcan-py are documented here.

---

## [0.6.0] — 2026-03-16

### Added — RCAN v1.6 support (4 gaps closed)

#### Federation & Identity
- **GAP-16** `rcan.federation`: `RegistryTier` enum (root/authoritative/community), `FederationSyncType` enum (consent/revocation/key), `RegistryIdentity` dataclass, `FederationSyncPayload` dataclass. `TrustAnchorCache` with 24-hour TTL — `lookup()`, `discover_via_dns()` (reads `_rcan-registry.<domain>` TXT), `verify_registry_jwt()` (issuer/expiry/Ed25519 check). `make_federation_sync()` builder. `validate_cross_registry_command()` — enforces LoA ≥ 2 and trust cache check; ESTOP always allowed (P66 invariant). New `MessageType.FEDERATION_SYNC = 33`.
- **GAP-14** `rcan.identity`: `LevelOfAssurance` IntEnum (ANONYMOUS=1, EMAIL_VERIFIED=2, HARDWARE_TOKEN=3). `IdentityRecord` dataclass. `extract_loa_from_jwt()` — JWT payload parsing without verification, graceful fallback to ANONYMOUS. `validate_loa_for_scope()` — scope-based LoA gating with configurable `min_loa_overrides` and `LoaPolicy`. `DEFAULT_LOA_POLICY` (all LoA=1, backward compatible). `PRODUCTION_LOA_POLICY` (control≥2, safety≥3). New `loa: Optional[int]` field on `RCANMessage`.

#### Constrained Transport
- **GAP-17** `rcan.transport`: `TransportEncoding` enum (HTTP/COMPACT/MINIMAL/BLE). `encode_compact()` / `decode_compact()` — msgpack (if available) or compact JSON with abbreviated field names. `encode_minimal()` / `decode_minimal()` — 32-byte ESTOP-only binary format with from/to RRN hashes, HMAC-SHA256 truncated signature, XOR checksum. `encode_ble_frame()` / `decode_ble_frames()` — MTU-fragmented BLE frames with stream reassembly. `select_transport()` — safety messages prefer MINIMAL > COMPACT > BLE > HTTP. New `transport_encoding: Optional[str]` field on `RCANMessage`.

#### Multi-Modal Payloads
- **GAP-18** `rcan.multimodal`: `MediaEncoding` enum (BASE64/REF). `MediaChunk` dataclass. `add_media_inline()` — inline media with SHA-256 integrity, 64 KB size limit (`MediaSizeError`). `add_media_ref()` — external media reference. `validate_media_chunks()` — inline hash recomputation, ref hash format check. `make_training_data_message()` — TRAINING_DATA message with inline media. `StreamChunk` dataclass. `make_stream_chunk()` — incremental media stream helper. New `media_chunks: list` field on `RCANMessage`. New `MessageType.TRAINING_DATA = 34`, `MessageType.STREAM_CHUNK = 35`.

### Changed
- `rcan.version`: `SPEC_VERSION = "1.6"`, `SDK_VERSION = "0.6.0"`. Added v1.6 feature flags: `FEDERATED_CONSENT`, `CONSTRAINED_TRANSPORT`, `MULTIMODAL_PAYLOADS`, `IDENTITY_LOA`.
- `rcan.message.RCANMessage`: added `media_chunks`, `loa`, `transport_encoding` fields. Updated `to_dict()`/`from_dict()` serialization.
- `rcan.exceptions`: added `FederationError`, `IdentityError`.

### Breaking Changes
- None. All existing tests pass. New fields on `RCANMessage` are optional with safe defaults.

---

## [0.5.0] — 2026-03-16

### Added — RCAN v1.5 support (18 gaps closed)

#### Security & Safety
- **GAP-03** `rcan.replay`: `ReplayCache` with sliding-window seen-set; `validate_replay()`. Safety messages enforce 10s max window. Prevents replay attacks before signature verification.
- **GAP-04** `rcan.clock`: `ClockSyncStatus`, `check_clock_sync()`, `assert_clock_synced()`. NTP sync check via systemd-timesyncd, timedatectl, chronyc, or pool.ntp.org. Raises `ClockDriftError` if clock is unsynchronized.
- **GAP-09** `rcan.keys`: `KeyStore` with JWKS-compatible key history, `make_key_rotation_message()`. New `MessageType.KEY_ROTATION = 27`.
- **GAP-12** `rcan.version`: `SPEC_VERSION = "1.5"` as single source of truth. `validate_version_compat()` with MAJOR version enforcement. Registry now imports from `version.py`.

#### Robot Identity & Trust
- **GAP-01** `rcan.delegation`: `DelegationHop`, `add_delegation_hop()`, `validate_delegation_chain()`. Max 4 hops with Ed25519 per-hop signing.
- **GAP-02** `rcan.revocation`: `RevocationStatus`, `RevocationCache` (1h TTL), `check_revocation()`, `make_revocation_broadcast()`. New `MessageType.ROBOT_REVOCATION = 19`.
- **GAP-08** `rcan.message`: `SenderType` enum (robot/human/cloud_function/system). New `sender_type`, `cloud_provider` fields on `RCANMessage`. `make_cloud_relay_message()` helper.

#### Consent & Compliance
- **GAP-05** `rcan.consent`: `ConsentRequestPayload`, `ConsentGrantPayload`, `ConsentDenyPayload`, `make_consent_request/grant/deny()`, `validate_consent_message()`. `MessageType.CONSENT_REQUEST=20`, `CONSENT_GRANT=21`, `CONSENT_DENY=22`.
- **GAP-10** `rcan.training_consent`: `DataCategory` enum (VIDEO/AUDIO/LOCATION/BIOMETRIC/TELEMETRY), `TrainingConsentRequest`, `make_training_consent_request/grant/deny()`. EU AI Act Annex III §5 compliance. `MessageType.TRAINING_CONSENT_REQUEST=30/31/32`.

#### Reliability & Operations
- **GAP-06** `rcan.offline`: `OfflineModeManager`, `OfflineStatus`. Offline mode with cross-owner grace period. ESTOP always allowed (P66 invariant). New principals blocked.
- **GAP-07** `rcan.config_update`: `ConfigUpdateMessage`, `make_config_update()`, `validate_config_update()`. Safety fields require `scope='creator'`. SHA-256 config hash verification.
- **GAP-11** `rcan.qos`: `QoSLevel` (FIRE_AND_FORGET/ACKNOWLEDGED/EXACTLY_ONCE), `QoSManager` with retry + exponential backoff, `make_estop_with_qos()`. ESTOP ACK timeout triggers `SafetyHaltError`. New `MessageType.COMMAND_ACK=17`, `COMMAND_NACK=28`, `COMMAND_COMMIT=29`.

#### Fleet & Observability
- **GAP-13** Fleet broadcast: `group_id: Optional[str]` on `RCANMessage`. `MessageType.FLEET_COMMAND=23`.
- **GAP-15** Observer mode: `read_only: bool` field on `RCANMessage`. `MessageType.SUBSCRIBE=24`, `UNSUBSCRIBE=25`.
- **GAP-19** Physical presence: `presence_verified: bool`, `proximity_m: Optional[float]` on `RCANMessage`.
- **GAP-20** `rcan.fault`: `FaultCode` enum (25 standard codes), `FaultReport`, `make_fault_report()`. `MessageType.FAULT_REPORT=26`.

### Changed
- `SPEC_VERSION` = `"1.5"` (`rcan/version.py` is now single source of truth)
- `__version__` = `"0.5.0"`
- `rcan/registry.py` imports `SPEC_VERSION` from `rcan/version.py` (was hardcoded `"1.2"`)
- `rcan/validate.py` `_CURRENT_SPEC_VERSION` now imports from `rcan/version.py`
- `RCANMessage.from_dict()` validates version compatibility before any other check (GAP-12)
- All new `RCANMessage` fields are optional with sane defaults — fully backward compatible

### New Exceptions
`VersionIncompatibleError`, `ReplayAttackError`, `ClockDriftError`, `DelegationChainExceededError`, `DelegationVerificationError`, `QoSAckTimeoutError`, `SafetyHaltError`, `ConfigAuthorizationError`, `ConfigHashMismatchError`, `RevocationError`, `ConsentError`

### Tests
430 tests (was 287) — +143 new tests covering all v1.5 modules.

---

## [0.4.0] — 2026-03-13

### Changed
- `SPEC_VERSION` = `"1.4"`, `__spec_version__` = `"1.4"` — tracks RCAN v1.4 stable release
- Package version `0.3.1` → `0.4.0` (minor bump for spec version milestone)

### Added
- `rcan-validate --version` now reports `rcan-py 0.4.0 / spec 1.4`

---

## [0.3.1] — 2026-03-13

### Changed
- `SPEC_VERSION` updated to `"1.3"` (was `"1.2"`) — tracks RCAN v1.3 stable release (§21 Registry Integration, L4 conformance)
- `rcan/__init__.py`, `rcan/message.py`: `SPEC_VERSION` and `__spec_version__` = `"1.3"`

---

## [0.3.0] — 2026-03-06

### Added
- `rcan-validate --version` — prints version and spec compatibility
- `rcan-validate robot <rrn>` — validate live robot record from registry via NodeClient
- `rcan-validate config --strict` — treat warnings as errors, require canonical schema
- `rcan-validate node <url>` — validate node manifest from rcan.dev or any registry node
- `rcan-validate config --watch` — live re-validation on file changes (1s polling)
- Canonical JSON schema validation with 24h local cache (`~/.cache/rcan/schemas/`)
- `SPEC_VERSION = "1.2"` exported from `rcan` package
- RRN address space expansion: sequences 8→8-16 digits, prefix `[A-Z0-9]{2,8}` (backward compatible)
- mypy CI integration with `mypy.ini`

### Changed
- `rcan-validate config` now fetches canonical schema from rcan.dev by default (use `--no-schema` to skip)

## [0.2.0] — 2026-03-06
### Features
- `RegistryClient` — full async/sync CRUD for rcan.dev API (register, get, list, search, patch, delete)
- `RegistryClient.search()` — filter by manufacturer, model, or tier
- Exception hierarchy: `RCANError`, `RCANNotFoundError`, `RCANAuthError`, `RCANValidationError`, `RCANNetworkError`
- `TypedDicts` for config/message shapes (RCANConfig, RCANMetadata, RCANMessageEnvelope)
- Config validation hardening — required fields, version format, --json output
- Audit chain verification — HMAC chain integrity, --secret flag
- Async context manager support with proper session cleanup
- `py.typed` marker for mypy compatibility
- `__all__` exports from rcan package root
### CI
- Pre-commit hook: `.pre-commit-hooks.yaml`
- GitHub Action: `continuonai/rcan-py/.github/actions/validate-rcan@main`
- pyyaml added to dev dependencies

---

## [0.1.1] — 2026-03-06
### Features
- TypedDicts: RCANConfig, RCANMetadata, RCANAgentConfig, RCANMessageEnvelope in rcan/types.py
- Config validation hardening: required keys, rcan_version format, device_id check

---

## [0.1.0] — 2026-03-05
### Initial Release
- `RobotURI` — parse/build RCAN URIs
- `RCANMessage` — signed message envelope
- `ConfidenceGate`, `HiTLGate` — runtime safety gates
- `CommitmentRecord`, `AuditChain` — HMAC-chained audit ledger
- `RegistryClient` — async/sync rcan.dev API client
- Exception hierarchy: RCANError and subclasses
- `rcan-validate` CLI: message, config, audit, uri, all subcommands
- `py.typed` marker for mypy compatibility

## v1.2.1 (2026-03-27)

### Breaking Changes
- **Ed25519 fully removed** — `KeyPair` class raises `DeprecationWarning` and redirects to `MLDSAKeyPair`
- **`pq_sig` field removed** from wire format — `signature` field is now the sole ML-DSA-65 block
- **`sign_message()` simplified** — takes `(msg, mldsa_keypair)`, no `pq_keypair` kwarg
- **`verify_message()` simplified** — takes `(msg, trusted: list[MLDSAKeyPair])`, no `require_pq` kwarg

### Summary
Clean ML-DSA-65-only release. Bob (RRN-000000000001) is the first robot running this stack.
Q-Day timeline: ML-DSA-65 primary NOW (2026), Ed25519 sunset 2027, NIST deadline 2029.
