"""
rcan.clock — Time Synchronization (GAP-04).

Checks whether the system clock is synchronized via NTP/chrony before
allowing replay-sensitive operations. Unsynchronized clocks degrade the
security of GAP-03 replay prevention.

Spec: §8.4 — Clock Synchronization Requirements
"""

from __future__ import annotations

import logging
import platform
import subprocess
import time
from dataclasses import dataclass

from rcan.exceptions import ClockDriftError

logger = logging.getLogger(__name__)

_DEFAULT_MAX_DRIFT_S = 5.0


@dataclass
class ClockSyncStatus:
    """Clock synchronization status.

    Attributes:
        synchronized: True if clock is NTP-synchronized.
        offset_s:     Current clock offset in seconds (abs value).
        source:       Description of how the status was determined.
    """

    synchronized: bool
    offset_s: float
    source: str


def check_clock_sync() -> ClockSyncStatus:
    """Check whether the system clock is NTP-synchronized.

    On Linux, reads ``/run/systemd/timesync/synchronized`` or calls
    ``timedatectl show``. On other platforms, attempts an NTP query to
    ``pool.ntp.org`` and measures offset.

    Returns:
        :class:`ClockSyncStatus` describing sync state.
    """
    system = platform.system()

    if system == "Linux":
        return _check_linux()
    else:
        return _check_ntp_query()


def _check_linux() -> ClockSyncStatus:
    """Linux-specific check via systemd-timesyncd or timedatectl."""
    import os
    import pathlib

    # Method 1: check systemd timesync marker file
    sync_file = pathlib.Path("/run/systemd/timesync/synchronized")
    if sync_file.exists():
        return ClockSyncStatus(
            synchronized=True,
            offset_s=0.0,
            source="systemd-timesyncd marker file",
        )

    # Method 2: timedatectl show
    try:
        result = subprocess.run(
            ["timedatectl", "show", "--property=NTPSynchronized,TimeUSec"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = result.stdout
        ntp_synced = "NTPSynchronized=yes" in output
        if ntp_synced:
            return ClockSyncStatus(
                synchronized=True,
                offset_s=0.0,
                source="timedatectl show",
            )
        elif "NTPSynchronized=no" in output:
            return ClockSyncStatus(
                synchronized=False,
                offset_s=float("inf"),
                source="timedatectl show",
            )
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        pass

    # Method 3: chronyc tracking
    try:
        result = subprocess.run(
            ["chronyc", "tracking"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "System time" in line and "seconds" in line:
                    parts = line.split()
                    for i, p in enumerate(parts):
                        try:
                            offset = abs(float(p))
                            return ClockSyncStatus(
                                synchronized=offset < 5.0,
                                offset_s=offset,
                                source="chronyc tracking",
                            )
                        except ValueError:
                            continue
            # chronyc responded — assume synced if no error
            return ClockSyncStatus(
                synchronized=True,
                offset_s=0.0,
                source="chronyc tracking (offset unknown)",
            )
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        pass

    # Fall back to NTP query
    return _check_ntp_query()


def _check_ntp_query() -> ClockSyncStatus:
    """Query pool.ntp.org to measure clock offset."""
    try:
        import ntplib  # type: ignore[import]

        client = ntplib.NTPClient()
        response = client.request("pool.ntp.org", version=3, timeout=5)
        offset = abs(response.offset)
        return ClockSyncStatus(
            synchronized=offset < _DEFAULT_MAX_DRIFT_S,
            offset_s=offset,
            source="NTP query to pool.ntp.org",
        )
    except ImportError:
        logger.debug("ntplib not available — estimating clock sync via HTTP")
    except Exception as exc:
        logger.warning("NTP query failed: %s", exc)

    # Last resort: compare local time to a known HTTP server Date header
    return _check_http_time()


def _check_http_time() -> ClockSyncStatus:
    """Estimate clock offset via HTTP Date header as a last resort."""
    try:
        import urllib.request

        req = urllib.request.Request(
            "http://worldtimeapi.org/api/timezone/Etc/UTC",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            import json

            data = json.loads(resp.read())
            unix_time = float(data.get("unixtime", 0))
            if unix_time > 0:
                offset = abs(time.time() - unix_time)
                return ClockSyncStatus(
                    synchronized=offset < _DEFAULT_MAX_DRIFT_S,
                    offset_s=offset,
                    source="HTTP time API",
                )
    except Exception as exc:
        logger.warning("HTTP time check failed: %s", exc)

    # Cannot determine — assume unsynchronized to be safe
    return ClockSyncStatus(
        synchronized=False,
        offset_s=float("inf"),
        source="unknown (all checks failed)",
    )


def assert_clock_synced(max_drift_s: float = _DEFAULT_MAX_DRIFT_S) -> ClockSyncStatus:
    """Assert that the system clock is synchronized within *max_drift_s* seconds.

    Args:
        max_drift_s: Maximum tolerated drift in seconds (default 5.0).

    Returns:
        :class:`ClockSyncStatus` if synced.

    Raises:
        ClockDriftError: If clock is not synchronized or exceeds *max_drift_s*.
    """
    status = check_clock_sync()
    if not status.synchronized or status.offset_s > max_drift_s:
        raise ClockDriftError(
            f"System clock not synchronized (offset={status.offset_s:.2f}s, "
            f"max_drift={max_drift_s}s, source={status.source!r}). "
            "Ensure NTP is running: sudo systemctl start systemd-timesyncd"
        )
    return status


__all__ = ["ClockSyncStatus", "check_clock_sync", "assert_clock_synced", "ClockDriftError"]
