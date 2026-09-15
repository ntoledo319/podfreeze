"""The privacy claims must be enforced by tests, not by good intentions.

The storefront tells a security-conscious iOS team what does and does not leave their
machine. That is exactly the kind of claim that quietly becomes false when someone adds
a convenient lookup to a code path that used to be offline.

These tests intercept the socket and HTTP layers and assert what actually crosses the
wire.
"""
from __future__ import annotations

import io
import contextlib
import socket
import urllib.request
from pathlib import Path

import pytest

LOCK = (
    "PODS:\n  - FirebaseAuth (10.18.0)\n  - PrivateInternalPod (1.0)\n\n"
    "DEPENDENCIES:\n  - FirebaseAuth\n  - PrivateInternalPod\n\n"
    "SPEC REPOS:\n  trunk:\n    - FirebaseAuth\n    - PrivateInternalPod\n\n"
    "COCOAPODS: 1.15.2\n"
)


@pytest.fixture
def no_network(monkeypatch):
    """Record every connection attempt and refuse it."""
    attempts: list = []

    def spy(self, addr):
        attempts.append(addr)
        raise OSError("network blocked by test")

    monkeypatch.setattr(socket.socket, "connect", spy)
    return attempts


def test_free_scan_makes_zero_network_calls(tmp_path, capsys, no_network):
    """'The free scan is fully offline' is advertised. Prove it."""
    from podfreeze.cli import main

    lock = tmp_path / "Podfile.lock"
    lock.write_text(LOCK)
    rc = main([str(lock)])
    capsys.readouterr()
    assert rc == 0
    assert no_network == [], f"free scan attempted network calls: {no_network}"


def test_json_output_also_offline(tmp_path, capsys, no_network):
    from podfreeze.cli import main

    lock = tmp_path / "Podfile.lock"
    lock.write_text(LOCK)
    main(["--json", str(lock)])
    capsys.readouterr()
    assert no_network == [], f"--json attempted network calls: {no_network}"


def test_pro_never_transmits_lockfile_contents(tmp_path, monkeypatch):
    """Pro may send pod NAMES. It must never send the lockfile itself."""
    sent: list = []

    def spy(req, *a, **kw):
        url = req.get_full_url() if hasattr(req, "get_full_url") else str(req)
        sent.append((url, getattr(req, "data", None)))
        raise OSError("network blocked by test")

    monkeypatch.setattr(urllib.request, "urlopen", spy)

    from podfreeze.audit import run_audit, render_markdown

    proj = tmp_path / "App"
    proj.mkdir()
    (proj / "Podfile.lock").write_text(LOCK)

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        try:
            render_markdown(run_audit(tmp_path), tmp_path)
        except Exception:
            pass

    assert sent, "expected Pro to perform lookups; it performed none"
    for url, body in sent:
        assert body is None, f"Pro sent a request body: {body!r}"
        assert "PODS:" not in url, "lockfile content leaked into a URL"
        assert "COCOAPODS:" not in url, "lockfile content leaked into a URL"


def test_pro_only_contacts_documented_hosts(tmp_path, monkeypatch):
    """The FAQ names exactly two hosts. Contacting a third would make it false."""
    allowed = {"trunk.cocoapods.org", "raw.githubusercontent.com"}
    hosts: set = set()

    def spy(req, *a, **kw):
        url = req.get_full_url() if hasattr(req, "get_full_url") else str(req)
        from urllib.parse import urlparse

        hosts.add(urlparse(url).netloc)
        raise OSError("network blocked by test")

    monkeypatch.setattr(urllib.request, "urlopen", spy)

    from podfreeze.audit import run_audit, render_markdown

    proj = tmp_path / "App"
    proj.mkdir()
    (proj / "Podfile.lock").write_text(LOCK)

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        try:
            render_markdown(run_audit(tmp_path), tmp_path)
        except Exception:
            pass

    undocumented = hosts - allowed
    assert not undocumented, f"Pro contacted undocumented hosts: {sorted(undocumented)}"
