"""
Tests for cvewatch.
CLI: main.py fetch <CVE_ID> [--stack]
     main.py watch [--stack] [--cvss-min] [--interval] [--once]
     main.py digest [--days] [--stack] [--cvss-min] [--output]
"""
import sys
import os
import subprocess
import pytest


def run(*args):
    env = os.environ.copy()
    env.setdefault('OPENAI_API_KEY', 'sk-dummy')
    return subprocess.run(
        [sys.executable, "main.py"] + list(args),
        capture_output=True, text=True, env=env
    )


def test_root_help():
    r = run("--help")
    assert r.returncode == 0
    assert any(x in r.stdout for x in ["fetch", "watch", "digest"])


def test_fetch_help():
    r = run("fetch", "--help")
    assert r.returncode == 0
    assert "--stack" in r.stdout


def test_watch_help():
    r = run("watch", "--help")
    assert r.returncode == 0
    assert "--once" in r.stdout
    assert "--cvss-min" in r.stdout


def test_digest_help():
    r = run("digest", "--help")
    assert r.returncode == 0
    assert "--days" in r.stdout
    assert "--output" in r.stdout


def test_fetch_requires_cve_id():
    r = run("fetch")
    assert r.returncode != 0


def test_module_compiles():
    r = subprocess.run([sys.executable, "-m", "py_compile", "main.py"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
