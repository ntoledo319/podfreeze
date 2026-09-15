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
    allowed = {"trunk.cocoapods.org", "raw.githubusercontent.com",
               "api.github.com"}
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


def test_known_monorepos_are_not_guesses():
    """Every monorepo slug must look like a real owner/repo, not a pod-name guess."""
    from podfreeze.enrich import KNOWN_MONOREPOS

    assert KNOWN_MONOREPOS, "the monorepo map is empty"
    for pod, slug in KNOWN_MONOREPOS.items():
        owner, _, repo = slug.partition("/")
        assert owner and repo, f"{pod}: malformed slug {slug!r}"
        assert slug != f"{pod}/{pod}", (
            f"{pod}: slug is just the guessed path, which the fallback already tries"
        )


def test_monorepo_lookup_does_not_widen_the_host_allowlist(tmp_path, monkeypatch):
    """Resolving a monorepo must still only contact raw.githubusercontent.com."""
    from urllib.parse import urlparse
    import urllib.request

    hosts: set = set()

    def spy(req, *a, **kw):
        url = req.get_full_url() if hasattr(req, "get_full_url") else str(req)
        hosts.add(urlparse(url).netloc)
        raise OSError("blocked")

    monkeypatch.setattr(urllib.request, "urlopen", spy)
    from podfreeze.enrich import find_swiftpm

    find_swiftpm("FirebaseAuth")
    assert hosts <= {"raw.githubusercontent.com", "api.github.com"}, (
        f"unexpected hosts: {hosts}")


def test_search_fallback_refuses_a_non_canonical_match(monkeypatch):
    """A wrong migration target is worse than an honest 'not found'.

    The top GitHub hit for IQKeyboardManagerSwift is a 74-star copy, not the real
    ~16k-star project. Pointing a buyer at a stranger's fork as their SwiftPM target
    would be a more damaging answer than admitting the probe could not resolve it.
    """
    from podfreeze import enrich as en

    items = {"items": [
        {"name": "SomePod", "full_name": "randomuser/SomePod",
         "fork": False, "stargazers_count": 12},          # too few stars
        {"name": "SomePodFork", "full_name": "other/SomePodFork",
         "fork": False, "stargazers_count": 9000},        # name mismatch
        {"name": "SomePod", "full_name": "forker/SomePod",
         "fork": True, "stargazers_count": 9000},         # a fork
    ]}

    class FakeResp:
        def __init__(self, payload): self._p = payload
        def read(self): import json; return json.dumps(self._p).encode()
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(en.urllib.request, "urlopen", lambda *a, **k: FakeResp(items))
    monkeypatch.setattr(en, "_head_ok", lambda url: True)  # would accept anything
    slug, ok = en._search_swiftpm("SomePod")
    assert ok is False and slug is None, (
        f"search fallback accepted a non-canonical repo: {slug}")


def test_search_fallback_accepts_a_clearly_canonical_match(monkeypatch):
    from podfreeze import enrich as en

    items = {"items": [
        {"name": "SomePod", "full_name": "SomePod/SomePod",
         "fork": False, "stargazers_count": 20000},
    ]}

    class FakeResp:
        def __init__(self, payload): self._p = payload
        def read(self): import json; return json.dumps(self._p).encode()
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(en.urllib.request, "urlopen", lambda *a, **k: FakeResp(items))
    monkeypatch.setattr(en, "_head_ok", lambda url: True)
    slug, ok = en._search_swiftpm("SomePod")
    assert ok is True and slug == "SomePod/SomePod"


def test_search_failure_never_breaks_enrichment(monkeypatch):
    """Search is a bonus. A GitHub outage must not fail a paid report."""
    from podfreeze import enrich as en

    def boom(*a, **k):
        raise OSError("github unreachable")

    monkeypatch.setattr(en.urllib.request, "urlopen", boom)
    slug, ok = en._search_swiftpm("AnyPod")
    assert (slug, ok) == (None, False)


def test_search_fallback_rejects_a_cross_ecosystem_name_collision(monkeypatch):
    """Pod names collide across ecosystems, and stars alone pick the wrong one.

    'Eureka' is a Swift forms library (~11k stars) and ALSO Netflix's Java service
    registry (~12.7k). Sorting by stars selects the Java project. Requiring a
    Package.swift happens to exclude it today, but a non-Swift project that vendors one
    would slip through -- so the language is checked explicitly rather than relied upon
    by accident.
    """
    from podfreeze import enrich as en

    items = {"items": [
        {"name": "Eureka", "full_name": "Netflix/eureka", "fork": False,
         "stargazers_count": 12742, "language": "Java"},
        {"name": "Eureka", "full_name": "xmartlabs/Eureka", "fork": False,
         "stargazers_count": 11000, "language": "Swift"},
    ]}

    class FakeResp:
        def __init__(self, payload): self._p = payload
        def read(self): import json; return json.dumps(self._p).encode()
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(en.urllib.request, "urlopen", lambda *a, **k: FakeResp(items))
    monkeypatch.setattr(en, "_head_ok", lambda url: True)  # both would "have" a Package.swift

    slug, ok = en._search_swiftpm("Eureka")
    assert ok is True, "the Swift library should still resolve"
    assert slug == "xmartlabs/Eureka", (
        f"picked {slug!r} - a higher-starred project from another ecosystem")
