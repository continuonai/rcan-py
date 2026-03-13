# Changelog

All notable changes to rcan-py are documented here.

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
