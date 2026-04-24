"""rcan.manifest — read a ROBOT.md file and extract RCAN-relevant fields.

Cross-links the ROBOT.md file format (https://robotmd.dev) to rcan-py.
Operators can now go from a manifest on disk to a preconfigured RCAN
client without hand-copying the RRN, rcan_uri, or endpoint URL.

Usage:

    from rcan import from_manifest

    info = from_manifest("./ROBOT.md")
    print(info.rrn)            # "RRN-000000000003"
    print(info.rcan_uri)       # "rcan://rcan.dev/acme/so-arm101/1-0/bob-001"
    print(info.endpoint)       # "https://rcan.dev"

    # Hand the endpoint + RRN to RegistryClient:
    from rcan.registry import RegistryClient
    async with RegistryClient(base_url=info.endpoint) as rc:
        robot = await rc.get_robot(info.rrn)

YAML parsing uses PyYAML. If PyYAML is not installed, from_manifest raises
an ImportError with a helpful message. Install with `pip install rcan[manifest]`.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def _normalize_agent(agent: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    """Normalize the `agent` frontmatter block into the v3.2 runtimes[] shape.

    - ``None`` or empty dict → ``None`` (no agent declared).
    - Structured ``agent.runtimes[]`` → returned as-is.
    - Flat form (``agent.provider``/``agent.model`` without ``runtimes``) →
      wrapped in a single-entry ``runtimes[]`` with ``default: true``. A
      ``DeprecationWarning`` is emitted; flat form is scheduled for removal
      in rcan-spec v4.0.
    - Both flat keys AND ``runtimes[]`` present → raises ``ValueError`` (ambiguous).

    See rcan-spec v3.2 §8.6 Multi-Runtime Agent Declaration.
    """
    if not agent:
        return None

    runtimes = agent.get("runtimes")
    has_flat = "provider" in agent or "model" in agent

    if runtimes is not None and has_flat:
        raise ValueError(
            "agent block declares both flat 'provider'/'model' and runtimes[] — "
            "use one or the other. Flat form is deprecated; prefer runtimes[]."
        )

    if runtimes is not None:
        if not isinstance(runtimes, list):
            raise ValueError("agent.runtimes must be a list")
        return runtimes

    if has_flat:
        warnings.warn(
            "flat agent.provider/agent.model form is deprecated in rcan-spec v3.2; "
            "use agent.runtimes[] instead. Removal scheduled for v4.0.",
            DeprecationWarning,
            stacklevel=2,
        )
        entry: dict[str, Any] = {
            "id": "robot-md",
            "harness": "default",
            "default": True,
            "models": [
                {
                    "provider": agent["provider"],
                    "model": agent.get("model"),
                    "role": "primary",
                }
            ],
        }
        for passthrough in ("latency_budget_ms", "safety_stop", "vision_enabled"):
            if passthrough in agent:
                entry[passthrough] = agent[passthrough]
        return [entry]

    return None


def _validate_agent_runtimes(runtimes: list[dict[str, Any]]) -> list[str]:
    """Validate an agent.runtimes[] list per rcan-spec v3.2 §8.6 rules.

    Returns a list of human-readable error strings. Empty list means the
    structure is valid.

    Rules enforced:
    - Every entry MUST have non-empty string ``id`` and ``harness``.
    - If ``runtimes[]`` has two or more entries, exactly one MUST be
      ``default: true``.
    - Unknown per-entry fields are allowed (runtime-specific pass-through).
    """
    errors: list[str] = []
    defaults = 0
    for i, entry in enumerate(runtimes):
        if not isinstance(entry, dict):
            errors.append(f"runtimes[{i}] must be a mapping")
            continue
        if not entry.get("id"):
            errors.append(f"runtimes[{i}] missing required field: id")
        if not entry.get("harness"):
            errors.append(f"runtimes[{i}] missing required field: harness")
        if entry.get("default") is True:
            defaults += 1

    if len(runtimes) >= 2 and defaults != 1:
        errors.append(
            f"runtimes[] with {len(runtimes)} entries must have exactly one default: true "
            f"(found {defaults})"
        )
    return errors


@dataclass(frozen=True)
class ManifestInfo:
    """Extracted identity + network fields from a ROBOT.md manifest.

    Fields are `None` when the manifest doesn't declare them (e.g. an
    unregistered robot has no `rrn`). The raw `frontmatter` dict is always
    available for callers that need fields beyond this shortcut set.
    """

    rrn: str | None
    rcan_uri: str | None
    endpoint: str | None
    signing_alg: str | None
    public_resolver: str | None
    robot_name: str | None
    rcan_version: str | None
    frontmatter: dict[str, Any]


def _extract_frontmatter(text: str) -> dict[str, Any]:
    """Extract and parse the YAML frontmatter from a ROBOT.md file."""
    try:
        import yaml
    except ImportError as e:
        raise ImportError(
            "from_manifest requires PyYAML. Install with: "
            'pip install "rcan[manifest]"  # or: pip install pyyaml'
        ) from e

    if not text.startswith("---"):
        raise ValueError("file does not start with '---' — not a ROBOT.md manifest")

    # Find the closing fence after the leading one.
    end = text.find("\n---", 4)
    if end == -1:
        raise ValueError("unterminated frontmatter — no closing '---' found")

    yaml_body = text[4:end]
    fm = yaml.safe_load(yaml_body)
    if not isinstance(fm, dict):
        raise ValueError("frontmatter did not parse as a YAML mapping")
    return fm


def from_manifest(path: str | Path) -> ManifestInfo:
    """Read `path` and return a :class:`ManifestInfo` with RCAN fields filled in.

    Raises :class:`FileNotFoundError` if the file doesn't exist,
    :class:`ValueError` if the file is not a valid ROBOT.md (missing/malformed
    frontmatter fences), and :class:`ImportError` if PyYAML is not available.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"{p} does not exist")

    fm = _extract_frontmatter(p.read_text())

    metadata = fm.get("metadata") or {}
    network = fm.get("network") or {}

    rrn = metadata.get("rrn") or None
    rcan_uri = metadata.get("rcan_uri") or None
    endpoint = network.get("rrf_endpoint") or None
    signing_alg = network.get("signing_alg") or None
    robot_name = metadata.get("robot_name") or None
    rcan_version = str(fm["rcan_version"]) if fm.get("rcan_version") is not None else None

    public_resolver = f"https://rcan.dev/r/{rrn}" if rrn else None

    return ManifestInfo(
        rrn=rrn,
        rcan_uri=rcan_uri,
        endpoint=endpoint,
        signing_alg=signing_alg,
        public_resolver=public_resolver,
        robot_name=robot_name,
        rcan_version=rcan_version,
        frontmatter=fm,
    )
