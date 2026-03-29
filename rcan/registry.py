"""
RCAN Registry Client — query and register robots with rcan.dev.

Requires the ``httpx`` optional dependency:
    pip install rcan[http]

Example:
    import asyncio
    from rcan.registry import RegistryClient

    async def main():
        client = RegistryClient()  # no auth = read-only

        # Look up a robot
        robot = await client.get_robot("RRN-000000000042")
        print(robot.uri)

        # Register (requires API key)
        client = RegistryClient(api_key="rcan_...")
        result = await client.register(
            manufacturer="acme",
            model="robotarm",
            version="v2",
            device_id="unit-001",
        )
        print(result["rrn"])  # RRN-000000000043

    asyncio.run(main())
"""

from __future__ import annotations

from typing import Any

from rcan.address import RobotURI
from rcan.exceptions import RCANRegistryError, RCANTimeoutError
from rcan.message import SPEC_VERSION
from rcan.version import SPEC_VERSION


def _run_sync(coro):  # type: ignore[no-untyped-def]
    """Run a coroutine synchronously — works inside and outside running loops.

    * Outside a loop: uses ``asyncio.run``.
    * Inside a loop (FastAPI, Jupyter, etc.): uses ``anyio.from_thread.run_sync``
      when available, otherwise raises a clear ``RuntimeError`` with instructions.
    """
    import asyncio as _asyncio

    try:
        loop = _asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is None:
        return _asyncio.run(coro)

    # Inside a running loop — try anyio
    try:
        import concurrent.futures as _cf

        import anyio.from_thread as _aft

        with _cf.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(_asyncio.run, coro)
            return future.result(timeout=30)
    except ImportError:
        pass

    raise RuntimeError(
        "Cannot call a sync wrapper from inside a running event loop without anyio. "
        "Use `await client.get_robot(rrn)` instead, or install anyio: pip install anyio"
    )


DEFAULT_BASE_URL = "https://rcan.dev"
DEFAULT_TIMEOUT = 10.0


class RegistryClient:
    """
    Async client for the RCAN robot registry at rcan.dev.

    Args:
        api_key:  Registry API key (required for write operations).
        base_url: Registry base URL (default: https://rcan.dev).
        timeout:  HTTP request timeout in seconds.

    Read operations (get_robot, list_robots, search) are available
    without an API key. Write operations (register, update) require one.

    Requires ``httpx``:  pip install rcan[http]
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._client: Any = None  # httpx.AsyncClient — lazy init

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    async def get_robot(self, rrn: str) -> "RegistryEntry":
        """
        Look up a robot by RRN (Robot Registry Number).

        Args:
            rrn: e.g. ``"RRN-000000000042"``

        Returns:
            :class:`RegistryEntry` with URI, metadata, and verification tier.

        Raises:
            RCANRegistryError: If the robot is not found or request fails.
        """
        data = await self._get(f"/api/v1/robots/{rrn}")
        return RegistryEntry.from_dict(data)

    async def list_robots(
        self,
        manufacturer: str | None = None,
        model: str | None = None,
        page: int = 1,
        per_page: int = 20,
    ) -> "RegistryPage":
        """
        List robots in the registry with optional filters.

        Returns:
            :class:`RegistryPage` with entries and pagination info.
        """
        params: dict[str, Any] = {"page": page, "per_page": per_page}
        if manufacturer:
            params["manufacturer"] = manufacturer
        if model:
            params["model"] = model
        data = await self._get("/api/v1/robots", params=params)
        return RegistryPage.from_dict(data)

    async def search(
        self,
        *,
        manufacturer: str | None = None,
        model: str | None = None,
        tier: str | None = None,
    ) -> list[dict]:
        """Search robots by manufacturer, model, or tier.

        Args:
            manufacturer: Filter by manufacturer slug.
            model:        Filter by model slug.
            tier:         Filter by verification tier (e.g. ``"verified"``).

        Returns:
            List of raw robot dicts from the registry.
        """
        params = {
            k: v
            for k, v in {
                "manufacturer": manufacturer,
                "model": model,
                "tier": tier,
            }.items()
            if v
        }
        data = await self._get("/api/v1/robots/search", params=params)
        return data if isinstance(data, list) else data.get("results", [])

    def search_sync(self, **kwargs: Any) -> list[dict]:
        """Synchronous wrapper around :meth:`search`."""
        return _run_sync(self.search(**kwargs))

    # ------------------------------------------------------------------
    # Write operations (require API key)
    # ------------------------------------------------------------------

    async def register(
        self,
        manufacturer: str,
        model: str,
        version: str,
        device_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Register a new robot and mint an RRN.

        Args:
            manufacturer: Manufacturer slug (e.g. ``"acme"``).
            model:        Model slug (e.g. ``"robotarm"``).
            version:      Hardware version (e.g. ``"v2"``).
            device_id:    Per-unit identifier.
            metadata:     Optional metadata dict (description, weight_kg, dof, etc.)

        Returns:
            Dict with keys: ``rrn``, ``uri``, ``registered_at``, ``verification_tier``.

        Raises:
            RCANRegistryError: If registration fails or API key is missing.
        """
        self._require_auth()
        payload = {
            "manufacturer": manufacturer,
            "model": model,
            "version": version,
            "device_id": device_id,
            "rcan_version": SPEC_VERSION,  # single source of truth: rcan/message.py
            "metadata": metadata or {},
        }
        return await self._post("/api/v1/robots", payload)

    async def update(self, rrn: str, metadata: dict[str, Any]) -> dict[str, Any]:
        """
        Update a robot's metadata.

        Args:
            rrn:      Robot Registry Number.
            metadata: Fields to update.

        Returns:
            Updated robot record dict.
        """
        self._require_auth()
        return await self._patch(f"/api/v1/robots/{rrn}", metadata)

    # ------------------------------------------------------------------
    # Sync convenience wrappers
    # ------------------------------------------------------------------

    def get_robot_sync(self, rrn: str) -> "RegistryEntry":
        """Synchronous wrapper around :meth:`get_robot`."""
        import asyncio

        return asyncio.run(self.get_robot(rrn))

    def register_sync(self, **kwargs: Any) -> dict[str, Any]:
        """Synchronous wrapper around :meth:`register`."""
        import asyncio

        return asyncio.run(self.register(**kwargs))

    # ------------------------------------------------------------------
    # HTTP internals
    # ------------------------------------------------------------------

    async def _get_client(self) -> Any:
        try:
            import httpx
        except ImportError:
            raise ImportError(
                "httpx is required for the registry client. "
                "Install with: pip install rcan[http]"
            )
        if self._client is None or self._client.is_closed:
            headers = {"User-Agent": "rcan-py/0.1.0"}
            if self._api_key:
                headers["Authorization"] = f"Bearer {self._api_key}"
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                headers=headers,
                timeout=self._timeout,
            )
        return self._client

    async def _get(self, path: str, params: dict | None = None) -> dict:
        client = await self._get_client()
        try:
            resp = await client.get(path, params=params)
            return self._handle_response(resp)
        except Exception as exc:
            if "timeout" in str(exc).lower():
                raise RCANTimeoutError(f"Registry request timed out: {path}") from exc
            raise RCANRegistryError(f"Registry request failed: {exc}") from exc

    async def _post(self, path: str, payload: dict) -> dict:
        client = await self._get_client()
        try:
            resp = await client.post(path, json=payload)
            return self._handle_response(resp)
        except Exception as exc:
            raise RCANRegistryError(f"Registry POST failed: {exc}") from exc

    async def _patch(self, path: str, payload: dict) -> dict:
        client = await self._get_client()
        try:
            resp = await client.patch(path, json=payload)
            return self._handle_response(resp)
        except Exception as exc:
            raise RCANRegistryError(f"Registry PATCH failed: {exc}") from exc

    @staticmethod
    def _handle_response(resp: Any) -> dict:
        try:
            if resp.status_code == 404:
                raise RCANRegistryError(f"Not found (404): {resp.url}")
            if resp.status_code == 401:
                raise RCANRegistryError("Unauthorized — check your API key")
            if resp.status_code == 429:
                raise RCANRegistryError("Rate limited — slow down requests")
            resp.raise_for_status()
            return resp.json()
        except RCANRegistryError:
            raise
        except Exception as exc:
            raise RCANRegistryError(f"Unexpected registry response: {exc}") from exc

    def _require_auth(self) -> None:
        if not self._api_key:
            raise RCANRegistryError(
                "API key required for write operations. "
                "Get one at https://rcan.dev/register"
            )

    async def aclose(self) -> None:
        """Close the underlying HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def __aenter__(self) -> "RegistryClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


class RegistryEntry:
    """A robot entry from the RCAN registry."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RegistryEntry":
        return cls(data)

    @property
    def rrn(self) -> str:
        return self._data.get("rrn", "")

    @property
    def uri(self) -> RobotURI | None:
        uri_str = self._data.get("uri") or self._data.get("rcan_uri")
        if uri_str:
            try:
                return RobotURI.parse(uri_str)
            except Exception:
                return None
        return None

    @property
    def manufacturer(self) -> str:
        return self._data.get("manufacturer", "")

    @property
    def model(self) -> str:
        return self._data.get("model", "")

    @property
    def version(self) -> str:
        return self._data.get("version", "")

    @property
    def verification_tier(self) -> str:
        return self._data.get("verification_tier", "community")

    @property
    def metadata(self) -> dict[str, Any]:
        return self._data.get("metadata", {})

    @property
    def registered_at(self) -> str:
        return self._data.get("registered_at", "")

    def to_dict(self) -> dict[str, Any]:
        return self._data.copy()

    def __repr__(self) -> str:
        return f"RegistryEntry(rrn={self.rrn!r}, model={self.model!r}, tier={self.verification_tier!r})"


class RegistryPage:
    """A paginated list of registry entries."""

    def __init__(self, entries: list[RegistryEntry], meta: dict[str, Any]) -> None:
        self.entries = entries
        self.meta = meta

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RegistryPage":
        entries = [
            RegistryEntry.from_dict(r)
            for r in data.get("robots", data.get("results", []))
        ]
        return cls(entries, data.get("meta", {}))

    @property
    def total(self) -> int:
        return self.meta.get("total", len(self.entries))

    @property
    def page(self) -> int:
        return self.meta.get("page", 1)

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self):
        return iter(self.entries)

    def __repr__(self) -> str:
        return f"RegistryPage(total={self.total}, count={len(self.entries)})"
