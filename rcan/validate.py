"""
rcan-validate — validate RCAN messages, configs, and audit chains.

CLI entry point and programmatic API for checking RCAN v1.2 compliance.

Usage:
    rcan-validate message command.json
    rcan-validate config robot.rcan.yaml
    rcan-validate audit audit-chain.jsonl
    rcan-validate uri 'rcan://registry.rcan.dev/acme/arm/v2/unit-001'
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
import sys
from dataclasses import dataclass, field
from typing import Any


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
# Validators
# ---------------------------------------------------------------------------


def validate_uri(uri_str: str) -> ValidationResult:
    """Validate a RCAN Robot URI string."""
    result = ValidationResult()
    try:
        from rcan.address import RobotURI
        uri = RobotURI.parse(uri_str)
        result.note(f"✅ Valid RCAN URI")
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

    Checks:
    - Required fields: rcan, cmd, target
    - RCAN version format
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

    # Required fields
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


def validate_config(config: dict | str) -> ValidationResult:
    """
    Validate a robot RCAN YAML config dict.

    Checks L1/L2/L3 conformance levels.
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

    import re

    # Required top-level keys
    for req_key in ("rcan_version", "metadata", "agent"):
        if req_key not in config:
            result.fail(f"Missing required key: '{req_key}'")

    # rcan_version format check
    rcan_version = config.get("rcan_version") or config.get("rcan_protocol", {}).get("version", "")
    if rcan_version:
        if not re.match(r"^\d+\.\d+$", str(rcan_version)):
            result.fail(
                f"rcan_version '{rcan_version}' must match pattern N.N (e.g. '1.2')"
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

    # RRN check
    if meta.get("rrn"):
        result.note(f"✅ RRN registered: {meta['rrn']}")
    else:
        result.warn("Robot not registered — run: castor register")

    if result.ok and not result.issues:
        l1_ok = not any("L1" in i for i in result.issues + result.warnings)
        l2_ok = l1_ok and not any("L2" in i for i in result.warnings)
        l3_ok = l2_ok and not any("L3" in i for i in result.warnings)
        level = "L3" if l3_ok else "L2" if l2_ok else "L1" if l1_ok else "FAIL"
        result.note(f"✅ Config valid — conformance level: {level}")
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
        secret = os.environ.get("OPENCASTOR_COMMITMENT_SECRET", "opencastor-default-commitment-secret")

    try:
        from rcan import CommitmentRecord
        import hashlib, hmac

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
                    result.fail(f"Line {i+1}: parse error — {e}")
                    return result

        if not records:
            result.warn("Audit chain is empty")
            return result

        prev_hash: str | None = None
        for lineno, record in records:
            # HMAC check
            if not record.verify(secret):
                result.fail(f"Line {lineno}: HMAC invalid (record_id={record.record_id[:8]})")
            # Chain linkage
            if prev_hash is not None and record.previous_hash != prev_hash:
                result.fail(f"Line {lineno}: chain broken (expected prev={prev_hash[:12]}, got {str(record.previous_hash)[:12]})")
            prev_hash = record.content_hash

        if result.ok:
            result.note(f"✅ Audit chain valid: {len(records)} records, chain intact")
    except FileNotFoundError:
        result.fail(f"File not found: {path}")
    except Exception as e:
        result.fail(f"Audit chain validation error: {e}")

    return result


# ---------------------------------------------------------------------------
# CLI entry point
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

    parser = argparse.ArgumentParser(
        prog="rcan-validate",
        description="Validate RCAN messages, configs, and audit chains",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_msg = sub.add_parser("message", help="Validate a RCAN message JSON file")
    p_msg.add_argument("file", help="JSON file or '-' for stdin")

    p_cfg = sub.add_parser("config", help="Validate a robot RCAN YAML config")
    p_cfg.add_argument("file", help="YAML config file")

    p_audit = sub.add_parser("audit", help="Verify a JSONL commitment chain")
    p_audit.add_argument("file", help="JSONL audit chain file")
    p_audit.add_argument(
        "--secret",
        default=None,
        help="HMAC secret for verification (overrides OPENCASTOR_COMMITMENT_SECRET env var)",
    )

    p_uri = sub.add_parser("uri", help="Validate a RCAN Robot URI")
    p_uri.add_argument("uri", help="URI string e.g. rcan://registry.rcan.dev/acme/arm/v2/unit-001")

    p_all = sub.add_parser("all", help="Run all applicable checks for a config")
    p_all.add_argument("file", help="YAML config file")

    for p in (p_msg, p_cfg, p_audit, p_uri, p_all):
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
            print(json.dumps({
                "ok": result.ok, "issues": result.issues,
                "warnings": result.warnings, "info": result.info
            }, indent=2))
        else:
            _print_result(result)
        return 0 if result.ok else 1

    if args.cmd == "config":
        result = validate_config(args.file)
        if getattr(args, "json", False):
            print(json.dumps({
                "ok": result.ok, "issues": result.issues,
                "warnings": result.warnings, "info": result.info
            }, indent=2))
        else:
            _print_result(result)
        return 0 if result.ok else 1

    if args.cmd == "audit":
        secret_arg = getattr(args, "secret", None)
        result = validate_audit_chain(args.file, secret=secret_arg)
        _print_result(result)
        return 0 if result.ok else 1

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
