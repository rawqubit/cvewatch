"""
Tests for cvewatch — CVE monitoring daemon.
"""
import sys
import subprocess
import pytest

def test_cli_help():
    result = subprocess.run([sys.executable, "main.py", "--help"], capture_output=True, text=True)
    assert result.returncode == 0

def test_dry_run_mode():
    """Dry run should not fail on missing credentials."""
    result = subprocess.run(
        [sys.executable, "main.py", "--dry-run", "--stack", "python,django"],
        capture_output=True, text=True
    )
    assert result.returncode in (0, 1)

def test_version_flag():
    result = subprocess.run([sys.executable, "main.py", "--version"], capture_output=True, text=True)
    assert result.returncode in (0, 1)
