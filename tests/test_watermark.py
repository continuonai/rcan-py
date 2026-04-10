"""Tests for rcan.watermark — AI output watermark SDK surface."""
import hashlib
import hmac as _hmac
import re

FAKE_KEY = b"x" * 64
RRN = "RRN-000000000001"
THOUGHT_ID = "thought-abc123"
TIMESTAMP = "2026-04-10T14:32:01.123456"


class TestComputeWatermarkToken:
    def test_basic(self):
        from rcan.watermark import compute_watermark_token
        token = compute_watermark_token(RRN, THOUGHT_ID, TIMESTAMP, FAKE_KEY)
        assert re.fullmatch(r"rcan-wm-v1:[0-9a-f]{32}", token)

    def test_matches_reference_algorithm(self):
        """Token must match: rcan-wm-v1:{hex(hmac_sha256(rrn:thought_id:timestamp, key)[:16])}"""
        from rcan.watermark import compute_watermark_token
        message = f"{RRN}:{THOUGHT_ID}:{TIMESTAMP}".encode()
        digest = _hmac.new(FAKE_KEY, message, hashlib.sha256).digest()
        expected = f"rcan-wm-v1:{digest[:16].hex()}"
        assert compute_watermark_token(RRN, THOUGHT_ID, TIMESTAMP, FAKE_KEY) == expected

    def test_deterministic(self):
        from rcan.watermark import compute_watermark_token
        assert (
            compute_watermark_token(RRN, THOUGHT_ID, TIMESTAMP, FAKE_KEY)
            == compute_watermark_token(RRN, THOUGHT_ID, TIMESTAMP, FAKE_KEY)
        )

    def test_different_inputs_give_different_tokens(self):
        from rcan.watermark import compute_watermark_token
        t1 = compute_watermark_token(RRN, THOUGHT_ID, TIMESTAMP, FAKE_KEY)
        t2 = compute_watermark_token("RRN-000000000002", THOUGHT_ID, TIMESTAMP, FAKE_KEY)
        assert t1 != t2


class TestVerifyTokenFormat:
    def test_valid(self):
        from rcan.watermark import compute_watermark_token, verify_token_format
        token = compute_watermark_token(RRN, THOUGHT_ID, TIMESTAMP, FAKE_KEY)
        assert verify_token_format(token) is True

    def test_invalid_prefix(self):
        from rcan.watermark import verify_token_format
        assert verify_token_format("rcan-wm-v2:" + "a" * 32) is False

    def test_invalid_short(self):
        from rcan.watermark import verify_token_format
        assert verify_token_format("rcan-wm-v1:abc123") is False

    def test_invalid_empty(self):
        from rcan.watermark import verify_token_format
        assert verify_token_format("") is False


class TestVerifyViaApi:
    def test_returns_entry_on_200(self):
        import asyncio
        from unittest.mock import AsyncMock, MagicMock, patch
        from rcan.watermark import verify_via_api

        token = "rcan-wm-v1:" + "a" * 32
        entry = {"event": "motor_command", "watermark_token": token}

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"valid": True, "audit_entry": entry}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        async def run():
            with patch("httpx.AsyncClient", return_value=mock_client):
                return await verify_via_api(token, "RRN-1", "http://robot.local:8000")

        result = asyncio.run(run())
        assert result == entry

    def test_returns_none_on_404(self):
        import asyncio
        from unittest.mock import AsyncMock, MagicMock, patch
        from rcan.watermark import verify_via_api

        mock_resp = MagicMock()
        mock_resp.status_code = 404

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        async def run():
            with patch("httpx.AsyncClient", return_value=mock_client):
                return await verify_via_api("rcan-wm-v1:" + "b" * 32, "RRN-1", "http://robot.local:8000")

        result = asyncio.run(run())
        assert result is None

    def test_raises_importerror_without_httpx(self):
        import asyncio
        import sys
        import pytest
        from unittest.mock import patch
        from rcan.watermark import verify_via_api

        async def run():
            with patch.dict(sys.modules, {"httpx": None}):
                await verify_via_api("rcan-wm-v1:" + "a" * 32, "RRN-1", "http://robot.local")

        with pytest.raises(ImportError, match="httpx"):
            asyncio.run(run())


class TestExports:
    def test_exported_from_rcan_package(self):
        import rcan
        assert hasattr(rcan, "compute_watermark_token")
        assert hasattr(rcan, "verify_token_format")
        assert hasattr(rcan, "verify_via_api")
