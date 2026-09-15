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


# ---------------------------------------------------------------------------
# The commercial promises. These are the claims that cost a buyer money or
# trust if they are quietly dropped, and they are the ones most tempting to
# soften later: every one of them costs a sale in order to be honest.
# ---------------------------------------------------------------------------


@pytest.mark.network
def test_refund_terms_survive():
    """'No argument, no time limit' is the promise that makes a $499 ask reasonable."""
    page = fetch(STOREFRONT).lower()
    assert "no argument" in page, "the refund promise lost 'no argument'"
    assert "no time limit" in page, "the refund promise gained a time limit"


@pytest.mark.network
def test_still_one_payment_not_a_subscription():
    page = fetch(STOREFRONT).lower()
    assert "one payment" in page or "nothing recurs" in page, (
        "the page no longer states this is a one-off payment"
    )
    for creep in ("per month", "/mo", "monthly subscription", "per year", "annually"):
        assert creep not in page, f"recurring pricing language appeared: {creep!r}"


@pytest.mark.network
def test_free_tier_is_still_described_as_uncrippled():
    """A free tier quietly limited later would make the paid tiers a bait-and-switch."""
    page = fetch(STOREFRONT).lower()
    assert "not crippled" in page or "not time-limited" in page, (
        "the storefront no longer promises the free tier is uncrippled"
    )


@pytest.mark.network
def test_downsell_survives():
    """Naming the case where the free tool is enough is the strongest honesty signal here.

    It is also the first sentence a revenue-minded edit would delete.
    """
    page = fetch(STOREFRONT)
    assert "do not need Pro" in page or "do not need the paid" in page, (
        "the storefront no longer tells people when they do NOT need to pay"
    )


@pytest.mark.network
def test_no_cve_claim_is_still_disclaimed():
    """Claiming CVE coverage would sell better and would be false.

    No vulnerability database covers the CocoaPods ecosystem: OSV.dev rejects
    'CocoaPods' as an invalid ecosystem and GitHub's advisory API returns 422.

    Note the phrasing: the page legitimately contains "CVE scanning" inside its own
    disclaimer ("any product claiming per-pod CVE scanning is either wrong or using a
    private dataset"). A naive substring check flags that honest sentence as an
    overclaim, so the test looks for a FIRST-PERSON claim instead.
    """
    page = fetch(STOREFRONT).lower()
    assert "no cve" in page or "no vulnerability database" in page, (
        "the disclaimer that this tool reports no CVE data has disappeared"
    )
    for overclaim in ("we scan for cve", "cve coverage included", "finds vulnerabilities",
                      "podfreeze scans for vulnerabilities", "vulnerability scanning included"):
        assert overclaim not in page, f"storefront now claims CVE coverage: {overclaim!r}"


@pytest.mark.network
def test_offline_licence_verification_still_promised():
    page = fetch(STOREFRONT).lower()
    assert "offline" in page and ("no phone-home" in page or "phone home" in page
                                 or "air-gapped" in page), (
        "the offline licence verification promise is gone"
    )
