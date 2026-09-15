"""Published figures must agree across every surface that states them.

The findings appear in three places: findings.html (prose), findings.json (data) and
the README (summary). Version pins drifted across surfaces twice in this project's
history; numbers will do the same unless something checks.

These tests do not re-derive the measurements -- they assert the published surfaces
tell the same story, and that the honesty caveats have not been quietly dropped.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HTML = ROOT / "docs" / "findings.html"
DATA = ROOT / "docs" / "findings.json"
README = ROOT / "README.md"


def _data() -> dict:
    return json.loads(DATA.read_text(encoding="utf-8"))


def test_dataset_is_valid_and_complete():
    d = _data()
    for key in ("title", "measured_utc", "tool", "method", "sampling_caveat", "totals"):
        assert key in d, f"dataset missing {key!r}"
    t = d["totals"]
    assert t["projects_examined"] > 0
    assert t["sources_determinable"] + t["sources_undeterminable"] == t["projects_examined"], (
        "determinable + undeterminable must equal the total examined"
    )
    assert t["determinable_with_exposure"] + t["confirmed_clean"] == t["sources_determinable"]


def test_headline_percentage_agrees_across_surfaces():
    """96% in prose, 96.5 in data -- consistent rounding, not contradiction."""
    t = _data()["totals"]
    exact = 100 * t["determinable_with_exposure"] / t["sources_determinable"]
    assert abs(exact - t["determinable_exposure_pct"]) < 0.05, "dataset percentage is wrong"

    rounded = str(round(exact))
    html = HTML.read_text(encoding="utf-8")
    assert f"{rounded}%" in html, f"findings.html does not state {rounded}%"
    assert f"{rounded}%" in README.read_text(encoding="utf-8"), (
        f"README does not state {rounded}%"
    )


def test_sample_size_agrees_across_surfaces():
    n = str(_data()["totals"]["projects_examined"])
    assert n in HTML.read_text(encoding="utf-8"), "findings.html omits the sample size"
    assert n in README.read_text(encoding="utf-8"), "README omits the sample size"


def test_sampling_bias_is_stated_not_buried():
    """A percentage without its caveat is a misleading number."""
    html = HTML.read_text(encoding="utf-8").lower()
    assert "what this sample is not" in html, "the sampling caveat heading was removed"
    assert "does not return a random sample" in html, (
        "findings.html no longer says the sample is non-random"
    )
    assert "population estimate" in html, (
        "findings.html no longer warns against reading it as a population estimate"
    )
    caveat = _data()["sampling_caveat"].lower()
    assert "not a random sample" in caveat or "does not return a random sample" in caveat
    assert "population estimate" in caveat


def test_no_third_party_repository_names_published():
    """Naming other people's projects as exposed publishes a posture they did not consent to."""
    blob = DATA.read_text(encoding="utf-8")
    slugs = re.findall(r"\b[\w.-]+/[\w.-]+\b", blob)
    allowed = ("http", "CC0", "ntoledo319", "cocoapods", "github.com", "CocoaPods")
    leaked = [s for s in slugs if not any(a.lower() in s.lower() for a in allowed)]
    assert not leaked, f"third-party repository identifiers in the dataset: {sorted(set(leaked))}"


def test_dataset_licence_permits_reuse():
    """Data nobody may reuse is not a contribution."""
    assert "CC0" in _data()["licence"], "dataset must carry an open licence"


def test_publish_dates_in_prose_match_the_dataset():
    """Every date stated on the page must come from the dataset, not from memory.

    The page originally claimed 'Firebase effectively left CocoaPods years ago' on the
    strength of one pod. Checking the whole family showed the Firebase-branded pods are
    frozen at 2022 but their dependencies -- GoogleUtilities, GTMSessionFetcher,
    PromisesObjC -- shipped releases in 2026. The page understated the risk.
    """
    import re as _re

    d = _data()
    by_pod = {p["pod"]: p for p in d["most_commonly_exposed_pods"]}
    html = HTML.read_text(encoding="utf-8")

    months = {"Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04", "May": "05",
              "Jun": "06", "Jul": "07", "Aug": "08", "Sep": "09", "Oct": "10",
              "Nov": "11", "Dec": "12"}

    rows = _re.findall(
        r"<tr><td><code>(\w+)</code></td><td>(\d{1,2}) (\w{3}) (\d{4})</td>", html)
    assert rows, "no pod/date rows found on the page"

    for pod, day, mon, year in rows:
        assert pod in by_pod, f"page names {pod}, which is not in the dataset"
        want = f"{year}-{months[mon]}-{int(day):02d}"
        got = by_pod[pod].get("last_published")
        assert got == want, f"{pod}: page says {want}, dataset says {got}"


def test_actively_publishing_pods_are_distinguished():
    """The page must separate 'already static' from 'still shipping'.

    Both are exposed, but only the second loses a live channel at the freeze. Collapsing
    them tells a reader the wrong thing about what to migrate first.
    """
    html = HTML.read_text(encoding="utf-8")
    assert "Which exposures actually change anything" in html, (
        "the section distinguishing live from static exposure was removed"
    )
    d = _data()
    live = [p for p in d["most_commonly_exposed_pods"]
            if p.get("last_published", "") >= "2025-01-01"]
    assert len(live) >= 5, (
        f"expected several actively-publishing pods in the dataset, found {len(live)}"
    )
