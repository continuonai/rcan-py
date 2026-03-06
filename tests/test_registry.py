"""Tests for rcan.registry — RegistryClient (mocked HTTP)."""

from __future__ import annotations

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from rcan.registry import RegistryClient, RegistryEntry, RegistryPage
from rcan.exceptions import RCANRegistryError


ROBOT_DATA = {
    "rrn": "RRN-00000042",
    "uri": "rcan://registry.rcan.dev/acme/arm/v2/unit-001",
    "manufacturer": "acme",
    "model": "arm",
    "version": "v2",
    "verification_tier": "community",
    "metadata": {"weight_kg": 1.2},
    "registered_at": "2026-03-05T00:00:00Z",
}


def make_mock_response(data: dict, status: int = 200):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = data
    resp.raise_for_status = MagicMock()
    if status >= 400:
        from httpx import HTTPStatusError
        resp.raise_for_status.side_effect = HTTPStatusError("error", request=None, response=resp)
    return resp


# ---------------------------------------------------------------------------
# RegistryEntry
# ---------------------------------------------------------------------------


def test_registry_entry_basic():
    entry = RegistryEntry.from_dict(ROBOT_DATA)
    assert entry.rrn == "RRN-00000042"
    assert entry.manufacturer == "acme"
    assert entry.model == "arm"
    assert entry.version == "v2"
    assert entry.verification_tier == "community"


def test_registry_entry_uri():
    entry = RegistryEntry.from_dict(ROBOT_DATA)
    uri = entry.uri
    assert uri is not None
    assert uri.manufacturer == "acme"
    assert uri.model == "arm"


def test_registry_entry_no_uri():
    entry = RegistryEntry.from_dict({"rrn": "RRN-00000001"})
    assert entry.uri is None


def test_registry_entry_repr():
    entry = RegistryEntry.from_dict(ROBOT_DATA)
    assert "RRN-00000042" in repr(entry)


# ---------------------------------------------------------------------------
# RegistryPage
# ---------------------------------------------------------------------------


def test_registry_page_basic():
    data = {"robots": [ROBOT_DATA, ROBOT_DATA], "meta": {"total": 2, "page": 1}}
    page = RegistryPage.from_dict(data)
    assert len(page) == 2
    assert page.total == 2
    assert page.page == 1


def test_registry_page_iter():
    data = {"robots": [ROBOT_DATA], "meta": {"total": 1}}
    page = RegistryPage.from_dict(data)
    entries = list(page)
    assert len(entries) == 1
    assert entries[0].rrn == "RRN-00000042"


# ---------------------------------------------------------------------------
# RegistryClient — auth guard
# ---------------------------------------------------------------------------


def test_register_requires_auth():
    client = RegistryClient()  # no api_key
    with pytest.raises(RCANRegistryError, match="API key required"):
        import asyncio
        asyncio.run(client.register(
            manufacturer="acme", model="arm", version="v2", device_id="x"
        ))


def test_update_requires_auth():
    client = RegistryClient()
    with pytest.raises(RCANRegistryError, match="API key required"):
        import asyncio
        asyncio.run(client.update("RRN-00000001", {"weight_kg": 1.0}))


# ---------------------------------------------------------------------------
# RegistryClient — missing httpx
# ---------------------------------------------------------------------------


def test_get_robot_no_httpx():
    client = RegistryClient()
    with patch.dict("sys.modules", {"httpx": None}):
        import asyncio
        with pytest.raises((ImportError, Exception)):
            asyncio.run(client.get_robot("RRN-00000001"))


# ---------------------------------------------------------------------------
# RegistryClient — mocked HTTP
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_robot_success():
    client = RegistryClient()
    mock_resp = make_mock_response(ROBOT_DATA)

    mock_httpx_client = AsyncMock()
    mock_httpx_client.get = AsyncMock(return_value=mock_resp)
    mock_httpx_client.is_closed = False

    with patch("httpx.AsyncClient", return_value=mock_httpx_client):
        # Prime the internal client
        client._client = mock_httpx_client
        entry = await client.get_robot("RRN-00000042")

    assert entry.rrn == "RRN-00000042"
    assert entry.manufacturer == "acme"


@pytest.mark.asyncio
async def test_list_robots_success():
    client = RegistryClient()
    data = {"robots": [ROBOT_DATA], "meta": {"total": 1, "page": 1}}
    mock_resp = make_mock_response(data)

    mock_httpx_client = AsyncMock()
    mock_httpx_client.get = AsyncMock(return_value=mock_resp)
    mock_httpx_client.is_closed = False
    client._client = mock_httpx_client

    page = await client.list_robots(manufacturer="acme")
    assert len(page) == 1


@pytest.mark.asyncio
async def test_register_success():
    client = RegistryClient(api_key="rcan_test_key")
    result_data = {
        "rrn": "RRN-00000043",
        "uri": "rcan://registry.rcan.dev/acme/arm/v2/unit-002",
        "registered_at": "2026-03-05T00:00:00Z",
    }
    mock_resp = make_mock_response(result_data, status=201)
    mock_resp.raise_for_status = MagicMock()

    mock_httpx_client = AsyncMock()
    mock_httpx_client.post = AsyncMock(return_value=mock_resp)
    mock_httpx_client.is_closed = False
    client._client = mock_httpx_client

    result = await client.register(
        manufacturer="acme", model="arm", version="v2", device_id="unit-002"
    )
    assert result["rrn"] == "RRN-00000043"


@pytest.mark.asyncio
async def test_get_robot_404():
    client = RegistryClient()
    mock_resp = make_mock_response({}, status=404)
    mock_resp.url = "/api/v1/robots/RRN-99999999"

    mock_httpx_client = AsyncMock()
    mock_httpx_client.get = AsyncMock(return_value=mock_resp)
    mock_httpx_client.is_closed = False
    client._client = mock_httpx_client

    with pytest.raises(RCANRegistryError, match="Not found"):
        await client.get_robot("RRN-99999999")
