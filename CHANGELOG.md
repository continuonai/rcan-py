# Changelog

All notable changes to rcan-py are documented here.

---

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
