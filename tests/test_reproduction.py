"""The reproduction script must stay correct, or the findings become uncheckable.

reproduce_findings.py is the only way a reader can verify the published 96% figure. If
it silently breaks, the claim quietly becomes unverifiable again -- and nothing would
report that, because the script is not imported by the package.

These tests exercise its pure logic (repo normalisation and the independent re-count)
without network access, so they run in CI on every commit.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "reproduce_findings.py"


def _load():
    spec = importlib.util.spec_from_file_location("reproduce_findings", SCRIPT)
    assert spec and spec.loader, "could not load reproduce_findings.py"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_script_exists_and_loads():
    assert SCRIPT.exists(), "the published reproduction script is missing"
    mod = _load()
    for fn in ("normalise_repo", "raw_facts", "collect", "main"):
        assert hasattr(mod, fn), f"reproduce_findings.py lost {fn}()"


@pytest.mark.parametrize("spelling,is_trunk", [
    ("trunk", True),
    ("master", True),
    ("https://github.com/CocoaPods/Specs", True),
    ("https://github.com/CocoaPods/Specs.git", True),
    ("https://github.com/cocoapods/specs.git", True),
    ("git@github.com:CocoaPods/Specs.git", True),
    ("https://cdn.cocoapods.org/", True),
    ("https://github.internal.corp/Specs.git", False),
    ("https://github.com/innovatrics/innovatrics-podspecs", False),
])
def test_reproduction_recognises_trunk_the_same_way_the_tool_does(spelling, is_trunk):
    """A reproduction that classifies differently would 'disprove' a correct finding."""
    mod = _load()
    got = mod.normalise_repo(spelling) in mod.TRUNK_ALIASES
    assert got is is_trunk, f"{spelling!r}: reproduction says trunk={got}, expected {is_trunk}"


def test_reproduction_matches_the_packages_own_classification():
    """The script's normalisation must agree with podfreeze itself.

    If they drift, a reader running the reproduction gets different numbers from the
    tool and reasonably concludes the published findings are wrong.
    """
    from podfreeze.parser import _normalise_repo, TRUNK_REPO_NORMALISED

    mod = _load()
    for spelling in ("trunk", "master", "https://github.com/CocoaPods/Specs",
                     "git@github.com:CocoaPods/Specs.git", "https://cdn.cocoapods.org",
                     "https://github.internal.corp/Specs.git"):
        pkg = _normalise_repo(spelling) in TRUNK_REPO_NORMALISED
        rep = mod.normalise_repo(spelling) in mod.TRUNK_ALIASES
        assert pkg == rep, (
            f"{spelling!r}: podfreeze says trunk={pkg}, reproduction says {rep}"
        )


def test_independent_recount_reads_the_raw_file():
    """raw_facts must derive counts from the text, not from the scanner."""
    mod = _load()
    text = (
        "PODS:\n  - Alamofire (5.8.1)\n  - React-Core (0.72.6):\n    - glog\n"
        "  - InternalPod (1.0)\n\n"
        "DEPENDENCIES:\n  - Alamofire\n\n"
        "SPEC REPOS:\n  https://github.com/CocoaPods/Specs:\n    - Alamofire\n"
        "    - React-Core\n"
        "  https://github.internal.corp/Specs.git:\n    - InternalPod\n\n"
        "COCOAPODS: 1.15.2\n"
    )
    roots, trunk, has_spec_repos = mod.raw_facts(text)
    assert has_spec_repos is True
    assert roots == {"Alamofire", "React-Core", "InternalPod"}, roots
    # the unsuffixed Specs URL is trunk; the corporate one is not
    assert trunk == {"Alamofire", "React-Core"}, trunk


def test_recount_reports_no_trunk_when_section_absent():
    """A legacy lockfile proves nothing about sources -- it must not invent exposure."""
    mod = _load()
    text = "PODS:\n  - Alamofire (3.0.0)\n\nDEPENDENCIES:\n  - Alamofire\n\nCOCOAPODS: 0.39.0\n"
    roots, trunk, has_spec_repos = mod.raw_facts(text)
    assert has_spec_repos is False
    assert roots == {"Alamofire"}
    assert trunk == set(), "no SPEC REPOS section cannot yield trunk-resolved pods"


def test_published_baseline_is_stated_for_comparison():
    """The script must print what the published run found, so a reader can compare."""
    src = SCRIPT.read_text(encoding="utf-8")
    assert "83 examined" in src and "96.5" in src, (
        "the script no longer states the published baseline it should be compared against"
    )
