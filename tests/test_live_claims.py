"""Claims on the live site must stay true after nobody is watching.

This operation ran a dozen guards by hand. Most need credentials and cannot survive it.
These four checks need nothing but network access, so they can run in CI on a schedule
and keep protecting the claims long after the person who wrote them has stopped looking.

Marked `network`; skipped automatically when the site is unreachable so a CI outage is
not reported as a false claim.
"""
from __future__ import annotations

import re
import urllib.error
import urllib.request

import pytest

STOREFRONT = "https://ntoledo319.github.io/podfreeze/"
CHECKER = "https://ntoledo319.github.io/podfreeze/check.html"
FINDINGS = "https://ntoledo319.github.io/podfreeze/findings.html"
DATASET = "https://ntoledo319.github.io/podfreeze/findings.json"
TIMEOUT = 20


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "podfreeze-selfcheck"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        pytest.skip(f"{url} unreachable ({e}) — not treating an outage as a false claim")


@pytest.mark.network
def test_storefront_states_the_freeze_date():
    page = fetch(STOREFRONT)
    assert "2 Dec 2026" in page or "2 December 2026" in page or "2026-12-02" in page, (
        "the storefront no longer states the date the whole product is about"
    )


@pytest.mark.network
def test_storefront_does_not_claim_the_build_breaks():
    """The core honesty claim: builds keep working, publishing stops.

    Overstating this is the easiest way to sell more and the fastest way to deserve a
    refund.
    """
    page = fetch(STOREFRONT).lower()
    assert "does not break" in page or "won't break" in page or "keep building" in page, (
        "the storefront no longer says builds keep working — the claim that keeps it honest"
    )
    for overclaim in ("your app will stop", "builds will fail", "breaks your build"):
        assert overclaim not in page, f"storefront now overclaims: {overclaim!r}"


@pytest.mark.network
def test_checker_still_says_nothing_is_uploaded():
    page = fetch(CHECKER).lower()
    assert "nothing is uploaded" in page or "runs entirely in your browser" in page, (
        "the browser checker no longer states that nothing is uploaded"
    )


@pytest.mark.network
def test_findings_keep_their_sampling_caveat():
    """A percentage without its caveat is a misleading number."""
    page = fetch(FINDINGS).lower()
    assert "what this sample is not" in page, "the sampling caveat section was removed"
    assert "does not return a random sample" in page
    assert "population estimate" in page


@pytest.mark.network
def test_dataset_totals_still_reconcile():
    import json

    d = json.loads(fetch(DATASET))
    t = d["totals"]
    assert t["sources_determinable"] + t["sources_undeterminable"] == t["projects_examined"]
    assert t["determinable_with_exposure"] + t["confirmed_clean"] == t["sources_determinable"]
    exact = 100 * t["determinable_with_exposure"] / t["sources_determinable"]
    assert abs(exact - t["determinable_exposure_pct"]) < 0.05, (
        "the published headline percentage no longer matches its own numbers"
    )


@pytest.mark.network
def test_install_command_on_the_site_is_pinned():
    page = fetch(STOREFRONT)
    assert re.search(r"podfreeze@v\d+\.\d+\.\d+", page), (
        "the storefront install command is not pinned to a release"
    )
    assert "podfreeze@main" not in page, (
        "the storefront tells people to install from an unprotected moving branch"
    )
