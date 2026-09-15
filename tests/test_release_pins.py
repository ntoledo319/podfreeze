"""Advertised install pins must match the version actually shipping.

Pinning to a tag is correct -- `@main` can serve an untested commit -- but it creates a
maintenance obligation that nothing enforced: v0.4.2 fixed a false "no SwiftPM target"
result while every install link still pointed at v0.4.1, so a buyer following the
storefront would have received the known-wrong build.

A stale pin is worse than no pin, because it looks deliberate.
"""
from __future__ import annotations

import re
from pathlib import Path

try:  # tomllib is stdlib on 3.11+; this package supports 3.9
    import tomllib  # type: ignore[import-not-found]

    def _load_toml(text: str) -> dict:
        return tomllib.loads(text)
except ModuleNotFoundError:  # pragma: no cover - exercised on 3.9/3.10 CI
    def _load_toml(text: str) -> dict:
        """Minimal read of the one field we need, without adding a dependency.

        Deliberately narrow: it reads `version = "..."` from the [project] table and
        nothing else. A parser that silently returned no version would disarm this
        test, so a missing version raises instead.
        """
        in_project = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("["):
                in_project = stripped == "[project]"
                continue
            if in_project:
                m = re.match(r'version\s*=\s*"([^"]+)"', stripped)
                if m:
                    return {"project": {"version": m.group(1)}}
        raise AssertionError("could not find project.version in pyproject.toml")

ROOT = Path(__file__).resolve().parent.parent
PIN_RE = re.compile(r"podfreeze@v(\d+\.\d+\.\d+)")


def shipping_version() -> str:
    data = _load_toml((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
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


def test_no_hardcoded_version_strings_in_workflows():
    """A bare version in CI goes stale the same way a pin does.

    `test "$V" = "podfreeze 0.4.2"` sat in install-matrix.yml and failed all ten legs
    on the v0.5.0 release -- the install was fine, the assertion was stale. The pin
    updater only rewrote `podfreeze@vX.Y.Z`, so a bare `X.Y.Z` slipped past it.
    Workflows must derive the version, never hardcode it.
    """
    want = shipping_version()
    wf_dir = ROOT / ".github" / "workflows"
    if not wf_dir.exists():
        return
    bare = re.compile(r'podfreeze (\d+\.\d+\.\d+)')
    offenders: list[str] = []
    for wf in wf_dir.glob("*.yml"):
        for found in bare.findall(wf.read_text(encoding="utf-8")):
            if found != want:
                offenders.append(f"{wf.name}: hardcoded {found}, shipping {want}")
    assert not offenders, (
        f"workflows assert a stale version: {offenders}. Derive it from the tag instead."
    )
