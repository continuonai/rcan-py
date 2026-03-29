"""Tests for rcan-validate --watch mode (Issue #8)."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

from rcan.validate import ValidationResult, watch_file

# ---------------------------------------------------------------------------
# watch_file unit tests
# ---------------------------------------------------------------------------


def test_watch_file_detects_change(tmp_path):
    """watch_file calls the callback when the file mtime changes."""
    watched = tmp_path / "robot.rcan.yaml"
    watched.write_text("rcan_version: '1.2'\n")

    call_count = 0
    mtimes_seen = []

    def fake_validate(path: str) -> ValidationResult:
        nonlocal call_count
        call_count += 1
        mtimes_seen.append(os.stat(path).st_mtime)
        return ValidationResult()

    # We'll run watch_file in a controlled way by mocking time.sleep and
    # os.stat to simulate two iterations: first a change, then a KeyboardInterrupt.
    original_stat = os.stat

    stat_calls = [0]

    def mock_stat(path):
        stat_calls[0] += 1
        result = original_stat(path)
        # Return a fake mtime that changes after the first check
        if stat_calls[0] == 1:
            # Simulate "no change yet" by returning the real stat
            return result

        # Simulate mtime advance
        class FakeStat:
            st_mtime = result.st_mtime + stat_calls[0]  # always different

        return FakeStat()

    # Patch sleep to raise KeyboardInterrupt on the 3rd call (exit loop)
    sleep_calls = [0]

    def mock_sleep(secs):
        sleep_calls[0] += 1
        if sleep_calls[0] >= 3:
            raise KeyboardInterrupt

    with (
        patch("os.stat", side_effect=mock_stat),
        patch("time.sleep", side_effect=mock_sleep),
    ):
        watch_file(str(watched), fake_validate)

    # The callback should have been called at least once (on the mtime change)
    assert call_count >= 1


def test_watch_file_handles_missing_file(tmp_path, capsys):
    """watch_file prints 'File not found' and retries when the file disappears."""
    missing = str(tmp_path / "gone.yaml")

    sleep_calls = [0]

    def mock_sleep(secs):
        sleep_calls[0] += 1
        if sleep_calls[0] >= 2:
            raise KeyboardInterrupt

    fake_validate = MagicMock(return_value=ValidationResult())

    with patch("time.sleep", side_effect=mock_sleep):
        watch_file(missing, fake_validate)

    captured = capsys.readouterr()
    assert "not found" in captured.out.lower() or "File not found" in captured.out
    # Validate should not have been called (file doesn't exist)
    fake_validate.assert_not_called()


def test_watch_file_calls_validate_on_first_read(tmp_path):
    """watch_file calls validate immediately on first mtime (mtime != 0)."""
    watched = tmp_path / "robot.rcan.yaml"
    watched.write_text("rcan_version: '1.2'\n")

    call_count = [0]

    def fake_validate(path: str) -> ValidationResult:
        call_count[0] += 1
        return ValidationResult()

    sleep_calls = [0]

    def mock_sleep(secs):
        sleep_calls[0] += 1
        if sleep_calls[0] >= 2:
            raise KeyboardInterrupt

    with patch("time.sleep", side_effect=mock_sleep):
        watch_file(str(watched), fake_validate)

    # Called at least once for the initial file read
    assert call_count[0] >= 1


def test_watch_file_no_double_validate(tmp_path):
    """watch_file does NOT call validate multiple times for the same mtime."""
    watched = tmp_path / "robot.rcan.yaml"
    watched.write_text("rcan_version: '1.2'\n")

    call_count = [0]

    def fake_validate(path: str) -> ValidationResult:
        call_count[0] += 1
        return ValidationResult()

    # Return same mtime every time → only one call expected
    fixed_mtime = os.stat(str(watched)).st_mtime

    class FixedStat:
        st_mtime = fixed_mtime

    sleep_calls = [0]

    def mock_sleep(secs):
        sleep_calls[0] += 1
        if sleep_calls[0] >= 4:
            raise KeyboardInterrupt

    with (
        patch("os.stat", return_value=FixedStat()),
        patch("time.sleep", side_effect=mock_sleep),
    ):
        watch_file(str(watched), fake_validate)

    # Should only be called once (the initial change from 0 → fixed_mtime)
    assert call_count[0] == 1
