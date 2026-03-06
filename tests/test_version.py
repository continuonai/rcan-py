"""Tests for rcan-validate --version flag (Issue #16)."""

import subprocess
import sys


def test_version_flag_output():
    """rcan-validate --version should print version and spec version."""
    result = subprocess.run(
        [sys.executable, "-m", "rcan.validate", "--version"],
        capture_output=True,
        text=True,
    )
    # argparse --version exits with code 0 and writes to stdout
    output = (
        result.stdout + result.stderr
    )  # argparse may write to stderr on some Pythons
    assert "0.2.0" in output, f"Version not found in output: {output!r}"
    assert "1.2" in output, f"Spec version not found in output: {output!r}"
    assert result.returncode == 0


def test_version_string_contents():
    """Version string should contain 'rcan-validate' prefix."""
    result = subprocess.run(
        [sys.executable, "-m", "rcan.validate", "--version"],
        capture_output=True,
        text=True,
    )
    output = result.stdout + result.stderr
    assert "rcan-validate" in output


def test_rcan_version_exports():
    """rcan package must export __version__ and SPEC_VERSION."""
    import rcan

    assert hasattr(rcan, "__version__"), "rcan.__version__ not exported"
    assert hasattr(rcan, "SPEC_VERSION"), "rcan.SPEC_VERSION not exported"
    assert rcan.__version__ == "0.2.0"
    assert rcan.SPEC_VERSION == "1.2"
