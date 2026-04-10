"""
rcan.watermark — AI output watermark tokens (RCAN §16.5).

SDK surface for computing and verifying RCAN watermark tokens. Consumers
that hold the robot's ML-DSA-65 private key can compute tokens; external
tools use verify_via_api to call the robot's public verification endpoint.

Token format: rcan-wm-v1:{hex(hmac_sha256(rrn:thought_id:timestamp, key)[:16])}
"""
from __future__ import annotations

import hashlib
import hmac
import re

WATERMARK_VERSION = "rcan-wm-v1"
WATERMARK_PATTERN = re.compile(r"^rcan-wm-v1:[0-9a-f]{32}$")


def compute_watermark_token(
    rrn: str,
    thought_id: str,
    timestamp: str,
    private_key_bytes: bytes,
) -> str:
    """Compute RCAN AI output watermark token per §16.5.

    Args:
        rrn: Robot Resource Name (e.g. ``"RRN-000000000001"``).
        thought_id: Unique ID of the Thought that produced the command.
        timestamp: ISO-8601 timestamp string.
        private_key_bytes: ML-DSA-65 private key bytes — the HMAC secret.

    Returns:
        Token string, e.g. ``"rcan-wm-v1:a3f9c1d2b8e47f20a3f9c1d2b8e47f20"``.
    """
    message = f"{rrn}:{thought_id}:{timestamp}".encode()
    digest = hmac.new(private_key_bytes, message, hashlib.sha256).digest()
    return f"{WATERMARK_VERSION}:{digest[:16].hex()}"


def verify_token_format(token: str) -> bool:
    """Return True if *token* matches ``rcan-wm-v1:{32 hex chars}``."""
    return bool(WATERMARK_PATTERN.match(token))


async def verify_via_api(
    token: str,
    rrn: str,
    base_url: str,
) -> dict | None:
    """Call the robot's public watermark verify endpoint.

    Args:
        token: Watermark token to verify.
        rrn: Robot Resource Name.
        base_url: Robot API base URL, e.g. ``"http://robot.local:8000"``.

    Returns:
        Audit entry dict if token is valid and in the audit log, else ``None``.

    Raises:
        ImportError: if ``httpx`` is not installed (``pip install httpx``).
    """
    try:
        import httpx
    except ImportError as exc:
        raise ImportError(
            "httpx is required for verify_via_api: pip install httpx"
        ) from exc

    url = f"{base_url.rstrip('/')}/api/v1/watermark/verify"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params={"token": token, "rrn": rrn})
    if resp.status_code == 200:
        return resp.json().get("audit_entry")
    return None
