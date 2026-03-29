"""Tests for rcan.clock — Time Synchronization (GAP-04)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from rcan.clock import ClockSyncStatus, assert_clock_synced, check_clock_sync
from rcan.exceptions import ClockDriftError


class TestClockSyncStatus:
    def test_synchronized_status(self):
        status = ClockSyncStatus(synchronized=True, offset_s=0.1, source="test")
        assert status.synchronized is True
        assert status.offset_s == 0.1
        assert status.source == "test"

    def test_unsynchronized_status(self):
        status = ClockSyncStatus(synchronized=False, offset_s=30.0, source="test")
        assert status.synchronized is False


class TestAssertClockSynced:
    def test_synced_clock_passes(self):
        status = ClockSyncStatus(synchronized=True, offset_s=0.5, source="test")
        with patch("rcan.clock.check_clock_sync", return_value=status):
            result = assert_clock_synced(max_drift_s=5.0)
            assert result.synchronized is True

    def test_unsynced_clock_raises(self):
        status = ClockSyncStatus(synchronized=False, offset_s=30.0, source="test")
        with patch("rcan.clock.check_clock_sync", return_value=status):
            with pytest.raises(ClockDriftError) as exc_info:
                assert_clock_synced(max_drift_s=5.0)
            assert (
                "not synchronized" in str(exc_info.value).lower()
                or "offset" in str(exc_info.value).lower()
            )

    def test_large_offset_raises(self):
        """Offset > max_drift_s should raise even if synchronized=True."""
        status = ClockSyncStatus(synchronized=True, offset_s=10.0, source="test")
        with patch("rcan.clock.check_clock_sync", return_value=status):
            with pytest.raises(ClockDriftError):
                assert_clock_synced(max_drift_s=5.0)

    def test_custom_max_drift(self):
        status = ClockSyncStatus(synchronized=True, offset_s=8.0, source="test")
        with patch("rcan.clock.check_clock_sync", return_value=status):
            result = assert_clock_synced(max_drift_s=10.0)
            assert result.synchronized is True


class TestCheckClockSync:
    """Test check_clock_sync returns a ClockSyncStatus regardless of platform."""

    def test_returns_clock_sync_status(self):
        """Should always return a ClockSyncStatus, never raise."""
        try:
            result = check_clock_sync()
            assert isinstance(result, ClockSyncStatus)
            assert isinstance(result.synchronized, bool)
            assert isinstance(result.offset_s, float)
            assert isinstance(result.source, str)
        except Exception as exc:
            pytest.fail(f"check_clock_sync raised unexpectedly: {exc}")

    def test_linux_timedatectl_path(self):
        """Test Linux timedatectl parsing path."""
        mock_result = MagicMock()
        mock_result.stdout = "NTPSynchronized=yes\nTimeUSec=1234567890\n"
        mock_result.returncode = 0

        with (
            patch("platform.system", return_value="Linux"),
            patch("pathlib.Path.exists", return_value=False),
            patch("subprocess.run", return_value=mock_result),
        ):
            status = check_clock_sync()
            assert isinstance(status, ClockSyncStatus)

    def test_linux_sync_file_path(self):
        """Test Linux sync marker file path."""
        with (
            patch("platform.system", return_value="Linux"),
            patch("pathlib.Path.exists", return_value=True),
        ):
            status = check_clock_sync()
            assert status.synchronized is True
            assert "timesyncd" in status.source

    def test_non_linux_falls_through(self):
        """Non-Linux path should return a status without raising."""
        with patch("platform.system", return_value="Darwin"):
            with patch("rcan.clock._check_ntp_query") as mock_ntp:
                mock_ntp.return_value = ClockSyncStatus(
                    synchronized=True, offset_s=0.1, source="mock"
                )
                status = check_clock_sync()
                assert isinstance(status, ClockSyncStatus)
