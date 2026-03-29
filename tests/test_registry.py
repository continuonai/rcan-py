"""Tests for rcan.registry — RegistryClient (mocked HTTP)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rcan.exceptions import RCANRegistryError
from rcan.registry import RegistryClient, RegistryEntry, RegistryPage

ROBOT_DATA = {
    "rrn": "RRN-000000000042",
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

        resp.raise_for_status.side_effect = HTTPStatusError(
            "error", request=None, response=resp
        )
    return resp


# ---------------------------------------------------------------------------
# RegistryEntry
# ---------------------------------------------------------------------------


def test_registry_entry_basic():
    entry = RegistryEntry.from_dict(ROBOT_DATA)
    assert entry.rrn == "RRN-000000000042"
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
    entry = RegistryEntry.from_dict({"rrn": "RRN-000000000001"})
    assert entry.uri is None


def test_registry_entry_repr():
    entry = RegistryEntry.from_dict(ROBOT_DATA)
    assert "RRN-000000000042" in repr(entry)


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
    assert entries[0].rrn == "RRN-000000000042"


# ---------------------------------------------------------------------------
# RegistryClient — auth guard
# ---------------------------------------------------------------------------


def test_register_requires_auth():
    client = RegistryClient()  # no api_key
    with pytest.raises(RCANRegistryError, match="API key required"):
        import asyncio

        asyncio.run(
            client.register(
                manufacturer="acme", model="arm", version="v2", device_id="x"
            )
        )


def test_update_requires_auth():
    client = RegistryClient()
    with pytest.raises(RCANRegistryError, match="API key required"):
        import asyncio

        asyncio.run(client.update("RRN-000000000001", {"weight_kg": 1.0}))


# ---------------------------------------------------------------------------
# RegistryClient — missing httpx
# ---------------------------------------------------------------------------


def test_get_robot_no_httpx():
    client = RegistryClient()
    with patch.dict("sys.modules", {"httpx": None}):
        import asyncio

        with pytest.raises((ImportError, Exception)):
            asyncio.run(client.get_robot("RRN-000000000001"))


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
        entry = await client.get_robot("RRN-000000000042")

    assert entry.rrn == "RRN-000000000042"
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
        "rrn": "RRN-000000000043",
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
    assert result["rrn"] == "RRN-000000000043"


@pytest.mark.asyncio
async def test_get_robot_404():
    client = RegistryClient()
    mock_resp = make_mock_response({}, status=404)
    mock_resp.url = "/api/v1/robots/RRN-000099999999"

    mock_httpx_client = AsyncMock()
    mock_httpx_client.get = AsyncMock(return_value=mock_resp)
    mock_httpx_client.is_closed = False
    client._client = mock_httpx_client

    with pytest.raises(RCANRegistryError, match="Not found"):
        await client.get_robot("RRN-000099999999")


# ---------------------------------------------------------------------------
# RegistryClient.search() — keyword filters
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_by_manufacturer():
    client = RegistryClient()
    results = [ROBOT_DATA]
    mock_resp = make_mock_response({"results": results})

    mock_httpx_client = AsyncMock()
    mock_httpx_client.get = AsyncMock(return_value=mock_resp)
    mock_httpx_client.is_closed = False
    client._client = mock_httpx_client

    data = await client.search(manufacturer="acme")
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["manufacturer"] == "acme"


@pytest.mark.asyncio
async def test_search_by_tier():
    client = RegistryClient()
    mock_resp = make_mock_response({"results": [ROBOT_DATA]})

    mock_httpx_client = AsyncMock()
    mock_httpx_client.get = AsyncMock(return_value=mock_resp)
    mock_httpx_client.is_closed = False
    client._client = mock_httpx_client

    data = await client.search(tier="community")
    assert isinstance(data, list)
    # Verify params passed to GET
    call_kwargs = mock_httpx_client.get.call_args
    params = call_kwargs.kwargs.get("params", {}) or {}
    assert "tier" in params


@pytest.mark.asyncio
async def test_search_no_filters_returns_list():
    client = RegistryClient()
    mock_resp = make_mock_response([ROBOT_DATA])

    mock_httpx_client = AsyncMock()
    mock_httpx_client.get = AsyncMock(return_value=mock_resp)
    mock_httpx_client.is_closed = False
    client._client = mock_httpx_client

    data = await client.search()
    assert isinstance(data, list)


@pytest.mark.asyncio
async def test_search_by_model():
    client = RegistryClient()
    mock_resp = make_mock_response({"results": [ROBOT_DATA]})

    mock_httpx_client = AsyncMock()
    mock_httpx_client.get = AsyncMock(return_value=mock_resp)
    mock_httpx_client.is_closed = False
    client._client = mock_httpx_client

    data = await client.search(model="arm")
    assert len(data) == 1


# ---------------------------------------------------------------------------
# Async context manager tests (#10)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_context_manager_opens_closes_session():
    """Async with RegistryClient closes the httpx session on exit."""
    async with RegistryClient() as client:
        # Force client creation
        mock_httpx = AsyncMock()
        mock_httpx.is_closed = False
        mock_httpx.aclose = AsyncMock()
        client._client = mock_httpx
        assert client._client is not None

    # aclose should have been called
    mock_httpx.aclose.assert_called_once()


@pytest.mark.asyncio
async def test_context_manager_closes_on_exception():
    """An exception inside the with block still closes the client."""
    mock_httpx = AsyncMock()
    mock_httpx.is_closed = False
    mock_httpx.aclose = AsyncMock()

    with pytest.raises(ValueError, match="boom"):
        async with RegistryClient() as client:
            client._client = mock_httpx
            raise ValueError("boom")

    mock_httpx.aclose.assert_called_once()


def test_search_sync_wrapper():
    """search_sync() returns a list (mock HTTP, no running loop)."""
    client = RegistryClient()
    mock_resp = make_mock_response({"results": [ROBOT_DATA]})

    mock_httpx_client = MagicMock()
    mock_httpx_client.is_closed = False

    # Patch the async get to return our mock response
    async def mock_get(*args, **kwargs):
        return mock_resp

    mock_httpx_client.get = mock_get
    client._client = mock_httpx_client

    result = client.search_sync(manufacturer="acme")
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["manufacturer"] == "acme"
