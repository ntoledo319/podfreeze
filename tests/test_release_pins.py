"""Advertised install pins must match the version actually shipping.

Pinning to a tag is correct -- `@main` can serve an untested commit -- but it creates a
maintenance obligation that nothing enforced: v0.4.2 fixed a false "no SwiftPM target"
result while every install link still pointed at v0.4.1, so a buyer following the
storefront would have received the known-wrong build.

A stale pin is worse than no pin, because it looks deliberate.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PIN_RE = re.compile(r"podfreeze@v(\d+\.\d+\.\d+)")


def shipping_version() -> str:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return data["project"]["version"]


def _pinned_files():
    for rel in ("README.md", "docs/index.html", "action.yml"):
        p = ROOT / rel
        if p.exists():
            yield p


def test_package_version_matches_dunder_version():
    from podfreeze import __version__

    assert __version__ == shipping_version(), (
        f"__init__ says {__version__}, pyproject says {shipping_version()}"
    )


def test_every_advertised_pin_matches_the_shipping_version():
    want = shipping_version()
    stale: list[str] = []
    found = 0
    for path in _pinned_files():
        for ver in PIN_RE.findall(path.read_text(encoding="utf-8")):
            found += 1
            if ver != want:
                stale.append(f"{path.name}: @v{ver}")
    assert found, "no advertised pins found at all -- has the install command moved?"
    assert not stale, (
        f"shipping version is {want} but these pins are stale: {stale}. "
        "A buyer following them receives an older build than the one being tested."
    )


def test_no_moving_refs_in_advertised_installs():
    """`@main` in user-facing docs hands people an unprotected, moving target."""
    offenders = [
        p.name for p in _pinned_files()
        if re.search(r"podfreeze@main", p.read_text(encoding="utf-8"))
        and p.name != "action.yml"  # action.yml only mentions it inside a comment
    ]
    assert not offenders, f"advertised install uses a moving ref in: {offenders}"
