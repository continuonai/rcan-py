"""
rcan-validate — validate RCAN messages, configs, and audit chains.

CLI entry point and programmatic API for checking RCAN v1.2 compliance.

Usage:
    rcan-validate message command.json
    rcan-validate config robot.rcan.yaml
    rcan-validate config robot.rcan.yaml --watch
    rcan-validate audit audit-chain.jsonl
    rcan-validate uri 'rcan://registry.rcan.dev/acme/arm/v2/unit-001'
    rcan-validate node https://registry.example.com
    rcan-validate node --file path/to/rcan-node.json
    rcan-validate all robot.rcan.yaml          # run all checks

Programmatic:
    from rcan.validate import validate_message, validate_config

    result = validate_message({"rcan": "1.2", "cmd": "stop", "target": "rcan://..."})
    if result.ok:
        print("valid")
    else:
        for issue in result.issues:
            print(f"  ⚠️  {issue}")
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

# ---------------------------------------------------------------------------
# RRN regex patterns (backward compatible — 8-digit sequences still valid)
# ---------------------------------------------------------------------------

# Root RRN: RRN-{8–16 digits}
RRN_RE = re.compile(r"^RRN-\d{8,16}$")

# Delegated RRN: RRN-{PREFIX}-{SEQUENCE}
# PREFIX: [A-Z0-9]{2,8} (alphanumeric, up to 8 chars)
# SEQUENCE: [0-9]{8,16} (8 to 16 digits → 10^16 capacity per namespace)
RRN_DELEGATED_RE = re.compile(r"^RRN-[A-Z0-9]{2,8}-\d{8,16}$")

# Combined: matches either form
RRN_ANY_RE = re.compile(r"^RRN(-[A-Z0-9]{2,8})?-\d{8,16}$")

_VALID_NODE_TYPES = {"root", "authoritative", "resolver", "cache"}


@dataclass
class ValidationResult:
    """Result of a validation check."""

    ok: bool = True
    issues: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    info: list[str] = field(default_factory=list)

    def fail(self, msg: str) -> None:
        self.ok = False
        self.issues.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    def note(self, msg: str) -> None:
        self.info.append(msg)


# ---------------------------------------------------------------------------
# Schema helpers (Part 3)
# ---------------------------------------------------------------------------


def _fetch_canonical_schema(schema_name: str) -> Optional[dict]:
    """Fetch a canonical schema from rcan.dev, with local 24h cache.

    Args:
        schema_name: Schema filename, e.g. ``"rcan-config.schema.json"``.

    Returns:
        Parsed schema dict, or ``None`` if unavailable (graceful degradation).
    """
    import os
    import time

    cache_dir = (
        Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
        / "rcan"
        / "schemas"
    )
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / schema_name

    # Return cached copy if fresh (< 24h)
    if cache_file.exists() and (time.time() - cache_file.stat().st_mtime) < 86400:
        try:
            return json.loads(cache_file.read_text())
        except Exception:
            pass  # corrupt cache — fall through to refetch

    try:
        url = f"https://rcan.dev/schemas/{schema_name}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            cache_file.write_text(json.dumps(data))
            return data
    except Exception:
        return None  # graceful degradation — network unreachable or schema not yet published


def _validate_against_schema(
    config: dict, schema: dict, result: ValidationResult
) -> None:
    """Validate *config* against *schema* using jsonschema if available."""
    try:
        import jsonschema  # type: ignore[import]

        validator = jsonschema.Draft7Validator(schema)
        errors = sorted(validator.iter_errors(config), key=lambda e: list(e.path))
        if errors:
            for err in errors:
                path = ".".join(str(p) for p in err.path) or "(root)"
                result.fail(f"Schema: {path}: {err.message}")
        else:
            result.note("  ✓ Canonical schema valid (rcan.dev)")
    except ImportError:
        result.warn(
            "jsonschema not installed — skipping canonical schema validation (pip install jsonschema)"
        )


# ---------------------------------------------------------------------------
# Watch mode helper (Part 4)
# ---------------------------------------------------------------------------


def watch_file(path: str, validate_fn: Callable[[str], ValidationResult]) -> None:
    """Poll *path* for changes and re-validate on each modification.

    Args:
        path:        Path to the file to watch.
        validate_fn: Callable that accepts the file path and returns a
                     :class:`ValidationResult`.
    """
    import os
    import time

    last_mtime = 0.0
    print(f"Watching {path} for changes (Ctrl+C to stop)...")
    try:
        while True:
            try:
                mtime = os.stat(path).st_mtime
                if mtime != last_mtime:
                    last_mtime = mtime
                    print(
                        f"\n[{time.strftime('%H:%M:%S')}] File changed — re-validating..."
                    )
                    result = validate_fn(path)
                    _print_result(result)
                time.sleep(1)
            except FileNotFoundError:
                print(f"File not found: {path}")
                time.sleep(2)
    except KeyboardInterrupt:
        print("\nStopped.")


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def validate_uri(uri_str: str) -> ValidationResult:
    """Validate a RCAN Robot URI string."""
    result = ValidationResult()
    try:
        from rcan.address import RobotURI

        uri = RobotURI.parse(uri_str)
        result.note("✅ Valid RCAN URI")
        result.note(f"   Registry:     {uri.registry}")
        result.note(f"   Manufacturer: {uri.manufacturer}")
        result.note(f"   Model:        {uri.model}")
        result.note(f"   Version:      {uri.version}")
        result.note(f"   Device ID:    {uri.device_id}")
    except Exception as e:
        result.fail(f"Invalid RCAN URI: {e}")
    return result


def validate_message(data: dict | str) -> ValidationResult:
    """
    Validate a RCAN message dict or JSON string.

    Accepts two message formats:

    1. **Wire format** (classic rcan-py): ``{rcan, cmd, target, ...}``
    2. **OpenCastor RCANMessage format**: ``{type, source, target, payload, ...}``

    For OpenCastor format:
    - ``source`` or ``source_ruri`` accepted as the source field
    - ``target`` or ``target_ruri`` accepted as the target field
    - ``type`` may be an int (MessageType enum value) or a string name

    Checks:
    - Required fields present (per detected format)
    - Target is a valid Robot URI
    - Confidence range [0.0, 1.0] if present
    - Signature structure if present
    """
    result = ValidationResult()

    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError as e:
            result.fail(f"Invalid JSON: {e}")
            return result

    # Detect format: OpenCastor RCANMessage vs classic wire format.
    # OpenCastor format is identified by the presence of a "type" field
    # (an integer or string MessageType enum value) without a "cmd" field.
    # Classic wire format uses "rcan" + "cmd" + "target".
    has_type = "type" in data
    has_cmd = "cmd" in data
    has_source = "source" in data or "source_ruri" in data
    has_target = "target" in data or "target_ruri" in data
    is_opencastor_format = has_type and not has_cmd

    if is_opencastor_format:
        # OpenCastor RCANMessage format — validate directly
        source = data.get("source") or data.get("source_ruri")
        target = data.get("target") or data.get("target_ruri")
        msg_type = data.get("type")

        if not source:
            result.fail("Missing required field: 'source' (or 'source_ruri')")
        if not target:
            result.fail("Missing required field: 'target' (or 'target_ruri')")
        if msg_type is None:
            result.fail("Missing required field: 'type'")

        if result.ok:
            # Validate type is int or recognized string
            if isinstance(msg_type, int):
                result.note(f"✅ RCAN message valid (OpenCastor format, type={msg_type})")
            elif isinstance(msg_type, str):
                result.note(f"✅ RCAN message valid (OpenCastor format, type={msg_type!r})")
            else:
                result.fail(f"'type' must be an int or string, got {type(msg_type).__name__}")

            if result.ok:
                # Validate target URI if it looks like an RCAN URI
                if isinstance(target, str) and target.startswith("rcan://"):
                    try:
                        from rcan.address import RobotURI
                        RobotURI.parse(target)
                        result.note(f"   target:   {target}")
                    except Exception:
                        result.warn(f"target URI may not be RFC-compliant: {target!r}")
                else:
                    result.note(f"   target:   {target}")

                result.note(f"   source:   {source}")
                result.warn("Message is unsigned (recommended for production)")
    else:
        # Classic wire format: {rcan, cmd, target}
        for field_name in ("rcan", "cmd", "target"):
            if field_name not in data:
                result.fail(f"Missing required field: '{field_name}'")

        if result.ok:
            try:
                from rcan.message import RCANMessage

                msg = RCANMessage.from_dict(data)
                result.note(f"✅ RCAN message valid (v{msg.rcan})")
                result.note(f"   cmd:      {msg.cmd}")
                result.note(f"   target:   {msg.target}")
                if msg.confidence is not None:
                    result.note(f"   confidence: {msg.confidence}")
                if msg.is_signed:
                    sig = msg.signature
                    result.note(f"   signature: alg={sig.get('alg')}, kid={sig.get('kid')}")
                else:
                    result.warn("Message is unsigned (recommended for production)")
                if not msg.is_ai_driven:
                    result.warn("No confidence score — add for RCAN §16 AI accountability")
            except Exception as e:
                result.fail(f"Message validation failed: {e}")

    return result


from rcan.version import SPEC_VERSION as _CURRENT_SPEC_VERSION  # type: ignore[assignment]


def validate_config(
    config: "dict | str",
    *,
    fetch_schema: bool = True,
    strict: bool = False,
) -> ValidationResult:
    """Validate a robot RCAN YAML config dict.

    Checks L1/L2/L3 conformance levels.  If *fetch_schema* is True, also
    attempts to validate against the canonical JSON schema from rcan.dev.

    Args:
        config:       Config dict or path to a YAML file.
        fetch_schema: Fetch and validate against the canonical JSON schema.
        strict:       Strict mode — warnings become errors, schema is required,
                      RRN format is validated if ``metadata.device_id`` is set,
                      and ``rcan_version`` must equal the current spec version.
    """
    result = ValidationResult()

    if isinstance(config, str):
        # Treat as YAML file path
        try:
            import yaml

            with open(config) as f:
                config = yaml.safe_load(f) or {}
        except FileNotFoundError:
            result.fail(f"Config file not found: {config}")
            return result
        except Exception as e:
            result.fail(f"Failed to parse config: {e}")
            return result

    # Required top-level keys
    for req_key in ("rcan_version", "metadata", "agent"):
        if req_key not in config:
            result.fail(f"Missing required key: '{req_key}'")

    # rcan_version format check
    rcan_version = config.get("rcan_version") or config.get("rcan_protocol", {}).get(
        "version", ""
    )
    if rcan_version:
        if not re.match(r"^\d+\.\d+(\.\d+)?(-[a-zA-Z0-9.]+)?$", str(rcan_version)):
            result.fail(
                f"rcan_version '{rcan_version}' must match pattern N.N or N.N.N (e.g. '1.2' or '1.2.0')"
            )
    else:
        result.warn("L1: rcan_version not declared (recommended)")

    # L1 checks
    meta = config.get("metadata", {})
    if not meta.get("manufacturer"):
        result.fail("L1: metadata.manufacturer is required (§2)")
    if not meta.get("model"):
        result.fail("L1: metadata.model is required (§2)")
    if not meta.get("version"):
        result.warn("L1: metadata.version not set")
    if not meta.get("device_id") and not meta.get("robot_name"):
        result.fail("L1: metadata.device_id (or robot_name) is required (§2)")

    # L2 checks
    rcan_proto = config.get("rcan_protocol", {})
    if not rcan_proto.get("jwt_auth", {}).get("enabled"):
        result.warn("L2: jwt_auth not enabled (required for L2 conformance, §8)")
    agent = config.get("agent", {})
    if not agent.get("confidence_gates"):
        result.warn("L2: confidence_gates not configured (§16)")

    # L3 checks
    if not agent.get("hitl_gates"):
        result.warn("L3: hitl_gates not configured (§16)")
    commitment = agent.get("commitment_chain", {})
    if not commitment.get("enabled"):
        result.warn("L3: commitment_chain not enabled (§16)")

    # RRN check — validate format if present
    rrn = meta.get("rrn")
    if rrn:
        if RRN_ANY_RE.match(str(rrn)):
            result.note(f"✅ RRN registered: {rrn}")
        else:
            result.fail(
                f"Invalid RRN format: '{rrn}'. "
                "Expected RRN-<8–16 digits> or RRN-<PREFIX>-<8–16 digits>."
            )
    else:
        result.warn("Robot not registered — run: castor register")

    # Strict mode extra checks
    if strict:
        # rcan_version must be current spec
        if rcan_version and str(rcan_version) != _CURRENT_SPEC_VERSION:
            result.fail(
                f"strict: rcan_version must be {_CURRENT_SPEC_VERSION!r} (got {rcan_version!r})"
            )
        # device_id that looks like an RRN must be valid format
        device_id = meta.get("device_id", "")
        if device_id and str(device_id).startswith("RRN-"):
            if not RRN_ANY_RE.match(str(device_id)):
                result.fail(
                    f"strict: metadata.device_id has invalid RRN format: {device_id!r}"
                )

    # Canonical JSON schema validation (Part 3)
    # In strict mode: always fetch schema; fail if unreachable
    effective_fetch_schema = fetch_schema or strict
    if effective_fetch_schema:
        schema = _fetch_canonical_schema("rcan-config.schema.json")
        if schema is not None:
            _validate_against_schema(config, schema, result)
        elif strict:
            result.fail(
                "strict: canonical schema from rcan.dev is required in strict mode but could not be fetched"
            )
        else:
            result.warn(
                "Could not fetch canonical schema from rcan.dev — skipping schema validation"
            )

    # In strict mode: promote warnings to errors
    if strict and result.warnings:
        for w in result.warnings:
            result.fail(f"strict: {w}")
        result.warnings.clear()

    if result.ok and not result.issues:
        l1_ok = not any("L1" in i for i in result.issues + result.warnings)
        l2_ok = l1_ok and not any("L2" in i for i in result.warnings)
        l3_ok = l2_ok and not any("L3" in i for i in result.warnings)
        level = "L3" if l3_ok else "L2" if l2_ok else "L1" if l1_ok else "FAIL"
        result.note(f"✅ Config valid — conformance level: {level}")
    return result


def validate_robot(rrn: str, node_url: str | None = None) -> ValidationResult:
    """Validate a robot record by RRN, fetching from a registry node.

    Args:
        rrn:      Robot Registry Number, e.g. ``"RRN-000000000001"``.
        node_url: Override the default registry URL (``https://rcan.dev``).

    Returns:
        :class:`ValidationResult` with per-check pass/fail details.
    """
    from rcan.node import NodeClient, RCANNodeError

    result = ValidationResult()
    client = NodeClient(root_url=node_url or "https://rcan.dev")

    try:
        raw = client.resolve(rrn)
        record: dict = raw.get("record", raw)
    except RCANNodeError as exc:
        result.fail(f"Could not fetch RRN: {exc}")
        return result

    # RRN format check
    if RRN_ANY_RE.match(rrn):
        result.note("  ✓ RRN format valid")
    else:
        result.fail(f"Invalid RRN format: {rrn}")

    # Required fields
    for req_field in ("name", "manufacturer", "model", "rcan_version"):
        if req_field in record:
            result.note(f"  ✓ {req_field}: {record[req_field]}")
        else:
            result.fail(f"Missing field: {req_field}")

    # Verification tier
    tier = record.get("verification_tier", "community")
    tier_badge: dict[str, str] = {
        "community": "⬜",
        "verified": "🟡",
        "certified": "🔵",
        "accredited": "✅",
    }
    result.note(f"  ℹ Verification tier: {tier_badge.get(tier, '?')} {tier}")

    # Canonical schema validation if available
    schema = _fetch_canonical_schema("rcan-robot.schema.json")
    if schema is not None:
        _validate_against_schema(record, schema, result)

    # Resolved-by info
    resolved_by = raw.get("resolved_by", node_url or "rcan.dev")
    result.info.insert(0, f"  Resolved by: {resolved_by}")
    result.info.insert(0, f"Validating robot record: {rrn}")

    passed = sum(1 for msg in result.info if msg.strip().startswith("✓"))
    failed = len(result.issues)
    result.note(
        f"\n{'PASS' if failed == 0 else 'FAIL'} ({passed}/{passed + failed} checks)"
    )

    return result


def validate_node(source: str, *, from_file: bool = False) -> ValidationResult:
    """Validate an RCAN node manifest.

    Args:
        source:    URL of a registry node (fetches ``/.well-known/rcan-node.json``)
                   or a local file path when *from_file* is ``True``.
        from_file: If ``True``, *source* is treated as a local file path.

    Returns:
        :class:`ValidationResult` with per-check pass/fail details.

    Exit codes (for CLI):
        * 0 — PASS
        * 1 — FAIL
        * 2 — WARN
    """
    import time

    result = ValidationResult()
    manifest: dict[str, Any] = {}

    if from_file:
        result.note(f"Validating node manifest: {source} (local file)")
        try:
            with open(source) as f:
                manifest = json.load(f)
        except FileNotFoundError:
            result.fail(f"File not found: {source}")
            return result
        except json.JSONDecodeError as e:
            result.fail(f"Invalid JSON: {e}")
            return result
    else:
        url = source.rstrip("/") + "/.well-known/rcan-node.json"
        result.note(f"Validating node manifest: {source}")
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "User-Agent": "rcan-validate/0.2"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                manifest = json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            result.fail(f"HTTP {exc.code} fetching {url}: {exc.reason}")
            return result
        except urllib.error.URLError as exc:
            result.fail(f"Network error fetching {url}: {exc.reason}")
            return result
        except json.JSONDecodeError as exc:
            result.fail(f"Invalid JSON from {url}: {exc}")
            return result
        except Exception as exc:
            result.fail(f"Unexpected error fetching {url}: {exc}")
            return result

    total = 0
    passed = 0

    def check_pass(msg: str) -> None:
        nonlocal total, passed
        total += 1
        passed += 1
        result.note(f"  ✓ {msg}")

    def check_fail(msg: str) -> None:
        nonlocal total
        total += 1
        result.fail(f"  ✗ {msg}")

    def check_warn(msg: str) -> None:
        nonlocal total
        total += 1
        result.warn(f"  ⚠ {msg}")

    # Required field checks
    required_fields = [
        "rcan_node_version",
        "node_type",
        "operator",
        "namespace_prefix",
        "public_key",
        "api_base",
    ]
    for fld in required_fields:
        if not manifest.get(fld):
            check_fail(f"Missing required field: '{fld}'")

    # Validate node_type
    node_type = manifest.get("node_type", "")
    if node_type in _VALID_NODE_TYPES:
        check_pass(f"node_type: {node_type}")
    elif manifest.get("node_type"):
        check_fail(
            f"node_type '{node_type}' invalid — must be one of: {', '.join(sorted(_VALID_NODE_TYPES))}"
        )

    # Validate public_key format
    pk = str(manifest.get("public_key", ""))
    if pk.startswith("ed25519:"):
        check_pass("public_key: ed25519: prefix present")
    elif pk:
        check_fail(f"public_key must start with 'ed25519:' (got: {pk[:20]!r}...)")

    # Validate api_base
    api_base = str(manifest.get("api_base", ""))
    if api_base.startswith("https://"):
        # Check reachability (HEAD request, 5s timeout)
        t0 = time.monotonic()
        try:
            req2 = urllib.request.Request(api_base, method="HEAD")
            with urllib.request.urlopen(req2, timeout=5):
                elapsed_ms = int((time.monotonic() - t0) * 1000)
                check_pass(f"api_base reachable ({elapsed_ms}ms)")
        except Exception:
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            check_warn(f"api_base not reachable ({elapsed_ms}ms) — may be intentional")
    elif api_base:
        check_fail(f"api_base must start with 'https://' (got: {api_base!r})")

    # namespace_prefix check
    ns = manifest.get("namespace_prefix", "")
    if ns:
        check_pass(f"namespace_prefix: {ns}")

    # Final summary
    status = (
        "PASS"
        if result.ok and not result.warnings
        else ("WARN" if result.ok else "FAIL")
    )
    result.note(f"\n{status} ({passed}/{total} checks)")

    return result


def validate_audit_chain(path: str, secret: str | None = None) -> ValidationResult:
    """
    Validate a JSONL audit chain file.

    Checks HMAC integrity and chain linkage for every record.

    Args:
        path:   Path to the JSONL audit chain file.
        secret: HMAC secret override.  Falls back to the
                ``OPENCASTOR_COMMITMENT_SECRET`` environment variable,
                then the built-in default.
    """
    result = ValidationResult()

    import os

    if secret is None:
        secret = os.environ.get(
            "OPENCASTOR_COMMITMENT_SECRET", "opencastor-default-commitment-secret"
        )

    try:
        from rcan import CommitmentRecord

        records = []
        with open(path) as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    record = CommitmentRecord.from_dict(data)
                    records.append((i + 1, record))
                except Exception as e:
                    result.fail(f"Line {i + 1}: parse error — {e}")
                    return result

        if not records:
            result.warn("Audit chain is empty")
            return result

        prev_hash: str | None = None
        for lineno, record in records:
            # HMAC check
            if not record.verify(secret):
                result.fail(
                    f"Line {lineno}: HMAC invalid (record_id={record.record_id[:8]})"
                )
            # Chain linkage
            if prev_hash is not None and record.previous_hash != prev_hash:
                result.fail(
                    f"Line {lineno}: chain broken (expected prev={prev_hash[:12]}, got {str(record.previous_hash)[:12]})"
                )
            prev_hash = record.content_hash

        if result.ok:
            result.note(f"✅ Audit chain valid: {len(records)} records, chain intact")
    except FileNotFoundError:
        result.fail(f"File not found: {path}")
    except Exception as e:
        result.fail(f"Audit chain validation error: {e}")

    return result


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------


def _print_result(result: ValidationResult, verbose: bool = True) -> None:
    """Print a ValidationResult to stdout."""
    for msg in result.info:
        print(msg)
    for msg in result.warnings:
        print(f"  ⚠️  {msg}")
    for msg in result.issues:
        print(f"  ❌ {msg}")
    if result.ok and not result.warnings:
        pass  # already printed via info
    elif not result.ok:
        print(f"\n  Result: INVALID ({len(result.issues)} error(s))")
    else:
        print(f"\n  Result: valid with {len(result.warnings)} warning(s)")


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for rcan-validate."""
    import argparse

    import rcan as _rcan_pkg

    parser = argparse.ArgumentParser(
        prog="rcan-validate",
        description="Validate RCAN messages, configs, and audit chains",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"rcan-validate {_rcan_pkg.__version__} (RCAN spec {_rcan_pkg.SPEC_VERSION})",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_msg = sub.add_parser("message", help="Validate a RCAN message JSON file")
    p_msg.add_argument("file", help="JSON file or '-' for stdin")

    p_cfg = sub.add_parser("config", help="Validate a robot RCAN YAML config")
    p_cfg.add_argument("file", help="YAML config file")
    p_cfg.add_argument(
        "--watch",
        action="store_true",
        help="Watch the file for changes and re-validate on each modification",
    )
    p_cfg.add_argument(
        "--no-schema",
        action="store_true",
        help="Skip canonical JSON schema validation from rcan.dev",
    )
    p_cfg.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Strict mode: treat warnings as errors, require canonical schema, "
            "validate RRN format in device_id, enforce current spec version"
        ),
    )

    p_audit = sub.add_parser("audit", help="Verify a JSONL commitment chain")
    p_audit.add_argument("file", help="JSONL audit chain file")
    p_audit.add_argument(
        "--secret",
        default=None,
        help="HMAC secret for verification (overrides OPENCASTOR_COMMITMENT_SECRET env var)",
    )

    p_uri = sub.add_parser("uri", help="Validate a RCAN Robot URI")
    p_uri.add_argument(
        "uri", help="URI string e.g. rcan://registry.rcan.dev/acme/arm/v2/unit-001"
    )

    p_node = sub.add_parser("node", help="Validate a RCAN registry node manifest")
    p_node_src = p_node.add_mutually_exclusive_group()
    p_node_src.add_argument(
        "url",
        nargs="?",
        help="Base URL of registry node (fetches /.well-known/rcan-node.json)",
    )
    p_node_src.add_argument(
        "--file",
        dest="node_file",
        metavar="PATH",
        help="Validate a local rcan-node.json file instead",
    )

    p_robot = sub.add_parser(
        "robot",
        help="Validate a robot record by RRN (fetches from registry node)",
    )
    p_robot.add_argument("rrn", help="Robot Registry Number, e.g. RRN-000000000001")
    p_robot.add_argument(
        "--node",
        dest="node_url",
        default=None,
        metavar="URL",
        help="Registry node URL (default: https://rcan.dev)",
    )

    p_all = sub.add_parser("all", help="Run all applicable checks for a config")
    p_all.add_argument("file", help="YAML config file")

    for p in (p_msg, p_cfg, p_audit, p_uri, p_node, p_robot, p_all):
        p.add_argument("--json", action="store_true", help="JSON output")

    args = parser.parse_args(argv)

    if args.cmd == "uri":
        result = validate_uri(args.uri)
        _print_result(result)
        return 0 if result.ok else 1

    if args.cmd == "message":
        if args.file == "-":
            data = json.load(sys.stdin)
        else:
            with open(args.file) as f:
                data = json.load(f)
        result = validate_message(data)
        if getattr(args, "json", False):
            print(
                json.dumps(
                    {
                        "ok": result.ok,
                        "issues": result.issues,
                        "warnings": result.warnings,
                        "info": result.info,
                    },
                    indent=2,
                )
            )
        else:
            _print_result(result)
        return 0 if result.ok else 1

    if args.cmd == "config":
        is_strict = getattr(args, "strict", False)
        # --no-schema is ignored in strict mode (schema always required)
        fetch_schema = (not getattr(args, "no_schema", False)) or is_strict
        if getattr(args, "watch", False):
            watch_file(
                args.file,
                lambda p: validate_config(
                    p, fetch_schema=fetch_schema, strict=is_strict
                ),
            )
            return 0
        result = validate_config(args.file, fetch_schema=fetch_schema, strict=is_strict)
        if getattr(args, "json", False):
            print(
                json.dumps(
                    {
                        "ok": result.ok,
                        "issues": result.issues,
                        "warnings": result.warnings,
                        "info": result.info,
                    },
                    indent=2,
                )
            )
        else:
            _print_result(result)
        return 0 if result.ok else 1

    if args.cmd == "robot":
        result = validate_robot(args.rrn, node_url=getattr(args, "node_url", None))
        if getattr(args, "json", False):
            print(
                json.dumps(
                    {
                        "ok": result.ok,
                        "issues": result.issues,
                        "warnings": result.warnings,
                        "info": result.info,
                    },
                    indent=2,
                )
            )
        else:
            _print_result(result)
        return 0 if result.ok else 1

    if args.cmd == "audit":
        secret_arg = getattr(args, "secret", None)
        result = validate_audit_chain(args.file, secret=secret_arg)
        _print_result(result)
        return 0 if result.ok else 1

    if args.cmd == "node":
        node_file = getattr(args, "node_file", None)
        url = getattr(args, "url", None)
        if node_file:
            result = validate_node(node_file, from_file=True)
        elif url:
            result = validate_node(url)
        else:
            parser.error("rcan-validate node requires a URL or --file PATH")
            return 1
        _print_result(result)
        # Exit 0=PASS, 1=FAIL, 2=WARN
        if not result.ok:
            return 1
        if result.warnings:
            return 2
        return 0

    if args.cmd == "all":
        print(f"\n📋 rcan-validate all — {args.file}\n")
        cfg_result = validate_config(args.file)
        print("Config:")
        _print_result(cfg_result)

        # If audit chain exists
        import os

        chain_path = ".opencastor-commitments.jsonl"
        if os.path.exists(chain_path):
            print(f"\nAudit chain ({chain_path}):")
            audit_result = validate_audit_chain(chain_path)
            _print_result(audit_result)

        ok = cfg_result.ok
        return 0 if ok else 1

    return 1


if __name__ == "__main__":
    sys.exit(main())
