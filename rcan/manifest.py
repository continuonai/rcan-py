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

from dataclasses import dataclass
from pathlib import Path
from typing import Any


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
