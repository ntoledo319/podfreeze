"""Regression tests against REAL Podfile.lock files from public iOS projects.

Every other fixture in this suite was written by me, which means every one encodes my
assumptions about the format. These five came from real public repositories via the
GitHub API and were never edited. Each expected result was verified by hand against the
raw lockfile before being recorded.

They cover shapes my own fixtures did not: a 2015-era lockfile written by CocoaPods
0.38.2 with no SPEC REPOS section at all, nested subspecs, and `:git` external sources.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent / "real_world"
EXPECTED = json.loads((FIXTURES / "expected.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_real_lockfile_classification(name, capsys):
    """Counts must match what the raw lockfile actually declares."""
    from podfreeze.analyse import analyse
    from podfreeze.parser import parse

    text = (FIXTURES / name).read_text(encoding="utf-8")
    report = analyse(parse(text))
    want = EXPECTED[name]

    assert report.examined == want["examined"], (
        f"{name}: examined {report.examined}, expected {want['examined']}"
    )
    exposed = [f for f in report.findings if f.category == "trunk"]
    assert len(exposed) == want["exposed"], (
        f"{name}: {len(exposed)} exposed, expected {want['exposed']}"
    )
    if "unknown" in want:
        unknown = [f for f in report.findings if f.category == "unknown"]
        assert len(unknown) == want["unknown"], (
            f"{name}: {len(unknown)} unknown, expected {want['unknown']}"
        )


def test_legacy_lockfile_never_guesses():
    """A 2015 lockfile has no SPEC REPOS. Absence of data must not become a finding.

    Reporting 'no pods exposed' for a file whose sources are undeterminable would be
    the most dangerous possible output: a clean bill of health nobody can act on.
    """
    from podfreeze.analyse import analyse
    from podfreeze.parser import parse

    text = (FIXTURES / "zpz1237_NirZhihuDaily2.0.lock").read_text(encoding="utf-8")
    assert "SPEC REPOS" not in text, "fixture no longer exercises the legacy path"

    report = analyse(parse(text))
    categories = {f.category for f in report.findings}
    assert "unknown" in categories, "undeterminable sources must be reported as unknown"
    assert not [f for f in report.findings if f.category == "trunk"], (
        "a lockfile with no SPEC REPOS cannot prove any pod resolves from trunk"
    )


def test_external_git_source_is_insulated():
    """`:git` in EXTERNAL SOURCES bypasses trunk entirely."""
    from podfreeze.analyse import analyse
    from podfreeze.parser import parse

    text = (FIXTURES / "zpz1237_NirZhihuDaily2.0.lock").read_text(encoding="utf-8")
    report = analyse(parse(text))
    swifty = [f for f in report.findings if f.pod.name == "SwiftyJSON"]
    assert swifty, "SwiftyJSON missing from the report"
    assert swifty[0].category == "external", (
        f"SwiftyJSON pinned via :git must be insulated, got {swifty[0].category}"
    )
