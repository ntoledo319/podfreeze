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


def test_trunk_url_without_git_suffix_is_not_private():
    """A real lockfile used the Specs URL WITHOUT '.git' and was called private.

    Classifying trunk as a private repo tells the user a pod is insulated from a
    freeze it is fully exposed to -- the most damaging error this tool can make.
    Matching must normalise, not enumerate punctuation.
    """
    from podfreeze.parser import _normalise_repo, TRUNK_REPO_NORMALISED

    for spelling in (
        "https://github.com/CocoaPods/Specs",
        "https://github.com/CocoaPods/Specs.git",
        "https://github.com/cocoapods/specs/",
        "git@github.com:CocoaPods/Specs.git",
        "https://cdn.cocoapods.org",
        "https://cdn.cocoapods.org/",
        "trunk",
        "master",
    ):
        assert _normalise_repo(spelling) in TRUNK_REPO_NORMALISED, (
            f"{spelling!r} must be recognised as trunk"
        )

    for private in (
        "https://github.internal.corp/Specs.git",
        "https://gitlab.example.com/ios/Specs",
        "git@github.com:AcmeCorp/Specs.git",
    ):
        assert _normalise_repo(private) not in TRUNK_REPO_NORMALISED, (
            f"{private!r} must NOT be treated as trunk"
        )


def test_quoted_subspec_name_is_parsed():
    """CocoaPods quotes names containing '+', e.g. "GoogleUtilities/NSData+zlib".

    A pod silently vanishing from an exposure report is the worst failure mode: the
    report looks complete and is not.
    """
    from podfreeze.parser import parse

    text = (FIXTURES / "quoted_subspec.lock").read_text(encoding="utf-8")
    lock = parse(text)
    raw = {p.raw_name for p in lock.pods}
    assert "GoogleUtilities/NSData+zlib" in raw, (
        f"quoted subspec dropped; parsed: {sorted(raw)}"
    )


def test_pod_from_unsuffixed_trunk_url_is_reported_exposed():
    """Exercise the real code path, not just the helper.

    Testing _normalise_repo directly does not prove Pod.from_trunk uses it -- reverting
    from_trunk to literal matching left the helper test passing while the product
    regressed. This asserts the end-to-end classification.
    """
    from podfreeze.analyse import analyse
    from podfreeze.parser import parse

    text = (FIXTURES / "quoted_subspec.lock").read_text(encoding="utf-8")
    report = analyse(parse(text))
    by_name = {f.pod.name: f.category for f in report.findings}
    assert by_name.get("GoogleUtilities") == "trunk", (
        f"GoogleUtilities under an unsuffixed Specs URL must be exposed, "
        f"got {by_name.get('GoogleUtilities')!r} — a false 'insulated' verdict"
    )
    assert by_name.get("Alamofire") == "trunk"


# Spec-repo spellings observed across 83 real public lockfiles. The first three are all
# the central index; the last two are genuinely private and must never be called trunk.
OBSERVED_REPOS = [
    ("trunk", True),
    ("https://github.com/CocoaPods/Specs", True),
    ("https://github.com/CocoaPods/Specs.git", True),
    ("https://github.com/cocoapods/specs.git", True),
    ("git@github.com:StandardCyborg/SCCocoaPods.git", False),
    ("https://github.com/innovatrics/innovatrics-podspecs", False),
]


@pytest.mark.parametrize("spelling,is_trunk", OBSERVED_REPOS)
def test_observed_spec_repo_spellings(spelling, is_trunk):
    """Every spelling seen in the wild must classify correctly.

    Three distinct spellings of the central index appeared across 83 real lockfiles.
    Treating any of them as private produces a false all-clear; treating a genuinely
    private repo as trunk produces a false alarm that gets the tool uninstalled.
    """
    from podfreeze.parser import _normalise_repo, TRUNK_REPO_NORMALISED

    got = _normalise_repo(spelling) in TRUNK_REPO_NORMALISED
    assert got is is_trunk, (
        f"{spelling!r}: classified trunk={got}, expected trunk={is_trunk}"
    )


def test_pro_ranks_actively_published_first():
    """--pro must agree with --audit on what to deal with first.

    The audit report was corrected in v0.5.0 but --pro kept ranking stalest-first and
    told buyers 'Actively-published pods are lower priority'. Two paid outputs giving
    opposite advice is worse than either being wrong alone.
    """
    from podfreeze.enrich import Enrichment
    from podfreeze.pro import _priority

    live = Enrichment(pod="GoogleUtilities", latest_version="8.1.3",
                      latest_published="2026-08-26", total_versions=77)
    stale = Enrichment(pod="SDWebImage", latest_version="5.9.5",
                       latest_published="2020-11-13", total_versions=100)

    assert _priority(live)[0] < _priority(stale)[0], (
        "an actively-published pod must rank ABOVE one static since 2020 — it is the "
        "one losing a live release channel at the freeze"
    )
    assert "loses a live release channel" in _priority(live)[1]
    assert "frozen already" in _priority(stale)[1]


def test_pro_order_of_work_text_is_not_backwards():
    """The prose must match the sort order it explains."""
    from podfreeze.pro import render_pro
    from podfreeze.analyse import analyse
    from podfreeze.parser import parse

    text = (FIXTURES / "quoted_subspec.lock").read_text(encoding="utf-8")
    out = render_pro(analyse(parse(text)), licensed=True)
    assert "Actively-published pods are lower priority" not in out, (
        "--pro still tells buyers actively-published pods matter less"
    )


def test_every_third_party_fixture_is_attributed():
    """Redistributing someone else's file requires knowing you may.

    A fixture was originally taken from a repository with NO licence file. No licence
    means all rights reserved, so redistributing it was not clearly permitted however
    mundane the content. Every remaining third-party fixture must be credited in
    ATTRIBUTION.md, which also records its licence.
    """
    attribution = (FIXTURES / "ATTRIBUTION.md")
    assert attribution.exists(), "third-party fixtures require an ATTRIBUTION.md"
    text = attribution.read_text(encoding="utf-8")

    authored = {"quoted_subspec.lock", "legacy_specs_url.lock"}
    for lock in sorted(FIXTURES.glob("*.lock")):
        if lock.name in authored:
            assert lock.name in text, f"{lock.name} should be listed as authored here"
            continue
        assert lock.name in text, (
            f"{lock.name} is redistributed third-party content with no attribution entry"
        )
        # the row naming it must also state a licence
        row = [ln for ln in text.splitlines() if lock.name in ln]
        assert any("MIT" in ln or "Apache" in ln or "BSD" in ln for ln in row), (
            f"{lock.name} is attributed but no permissive licence is recorded"
        )


def test_no_unlicensed_fixture_reintroduced():
    """The removed fixture must not come back."""
    assert not (FIXTURES / "beardedspice_beardedspice.lock").exists(), (
        "a fixture from an unlicensed repository was reintroduced"
    )


def test_audit_triages_instead_of_dumping_a_wall(tmp_path, monkeypatch):
    """A ranked list of 81 pods is a wall, not a plan.

    On a real 12-project tree the audit lists 81 exposed pods, 54% of them static for
    3+ years. Ranking them correctly is not enough -- the report must say how many
    actually change anything and name where to start.
    """
    from podfreeze import audit as audit_mod
    from podfreeze.enrich import Enrichment

    for i, (pod, pub) in enumerate([
        ("LivePod", "2026-08-01"), ("AlsoLive", "2026-05-01"),
        ("AgingPod", "2024-06-01"), ("FrozenPod", "2018-01-01"),
        ("AlsoFrozen", "2015-01-01"),
    ]):
        proj = tmp_path / f"App{i}"
        proj.mkdir()
        (proj / "Podfile.lock").write_text(
            f"PODS:\n  - {pod} (1.0)\n\nDEPENDENCIES:\n  - {pod}\n\n"
            f"SPEC REPOS:\n  trunk:\n    - {pod}\n\nCOCOAPODS: 1.15.2\n")

    dates = {"LivePod": "2026-08-01", "AlsoLive": "2026-05-01",
             "AgingPod": "2024-06-01", "FrozenPod": "2018-01-01",
             "AlsoFrozen": "2015-01-01"}

    def fake_enrich(names, workers=8):
        return [Enrichment(pod=n, latest_version="1.0",
                           latest_published=dates.get(n), total_versions=3)
                for n in names]

    monkeypatch.setattr(audit_mod, "enrich", fake_enrich)
    md = audit_mod.render_markdown(audit_mod.run_audit(tmp_path), tmp_path)

    assert "still publishing (lose a live channel)" in md, (
        "summary no longer triages exposed pods by whether they still publish")
    assert "already frozen in practice" in md
    assert "Start with the 2 pod(s) still publishing" in md, (
        "report no longer names where to start")
    # the starting pods must be the live ones, not the ancient ones
    start = md.split("Start with the", 1)[1][:200]
    assert "LivePod" in start and "FrozenPod" not in start


def test_free_scan_leads_with_a_summary_not_a_wall(tmp_path, capsys):
    """A real project exposes 69 pods. An alphabetical dump teaches nothing.

    The free tier cannot rank by publish date -- that needs network, and the free scan
    makes zero calls -- but it can state how many of the examined pods are exposed and
    how many face an earlier vendor cutoff, both computable offline.
    """
    from podfreeze.cli import main

    pods = [f"PodNum{i:02d}" for i in range(15)] + ["FirebaseAuth", "GoogleUtilities"]
    lock = tmp_path / "Podfile.lock"
    lock.write_text(
        "PODS:\n" + "".join(f"  - {p} (1.0)\n" for p in pods) + "\n"
        "DEPENDENCIES:\n" + "".join(f"  - {p}\n" for p in pods) + "\n"
        "SPEC REPOS:\n  trunk:\n" + "".join(f"    - {p}\n" for p in pods) + "\n"
        "COCOAPODS: 1.15.2\n")
    main([str(lock)])
    out = capsys.readouterr().out

    assert f"{len(pods)} of {len(pods)} pod(s) resolve from CocoaPods trunk" in out, (
        "the free scan no longer states the exposed-of-examined ratio up front")
    assert "2 of them face an EARLIER vendor cutoff" in out, (
        "the free scan no longer counts the pods with an earlier deadline")
    # the marker must land on the vendor pods and nothing else
    marked = [l for l in out.splitlines() if "earlier deadline" in l]
    assert len(marked) == 2, f"expected 2 marked pods, got {len(marked)}"
    assert any("FirebaseAuth" in l for l in marked)
    assert any("GoogleUtilities" in l for l in marked)
    assert not any("PodNum" in l for l in marked), "marker leaked onto unaffected pods"


def test_singular_grammar_when_one_pod_has_an_earlier_cutoff(tmp_path, capsys):
    """'1 of them face' is wrong; a report that reads badly reads as careless."""
    from podfreeze.cli import main
    lock = tmp_path / "Podfile.lock"
    lock.write_text(
        "PODS:\n  - FirebaseAuth (1.0)\n  - Alamofire (5.8.1)\n\n"
        "DEPENDENCIES:\n  - FirebaseAuth\n  - Alamofire\n\n"
        "SPEC REPOS:\n  trunk:\n    - FirebaseAuth\n    - Alamofire\n\nCOCOAPODS: 1.15.2\n")
    main([str(lock)])
    out = capsys.readouterr().out
    assert "1 of them faces an EARLIER" in out, "singular grammar regressed"


def test_free_scan_disclaims_vulnerability_data(tmp_path, capsys):
    """Mentioning CVEs without disclaiming them invites a false inference.

    The output says a pod "can never receive a CVE patch", which reads as though the
    tool knows something about vulnerabilities. It does not, and none honestly can: no
    vulnerability database covers CocoaPods. The paid report has disclaimed this since
    it shipped; the free tier -- run far more often -- did not.
    """
    from podfreeze.cli import main
    lock = tmp_path / "Podfile.lock"
    lock.write_text(
        "PODS:\n  - Alamofire (5.8.1)\n\nDEPENDENCIES:\n  - Alamofire\n\n"
        "SPEC REPOS:\n  trunk:\n    - Alamofire\n\nCOCOAPODS: 1.15.2\n")
    main([str(lock)])
    out = capsys.readouterr().out
    assert "CVE" in out, "fixture no longer exercises the CVE-mentioning branch"
    assert "reports NO vulnerability data" in out, (
        "the free scan mentions CVEs without disclaiming that it checks none")
    assert "can no longer RECEIVE a fix, not which" in out, (
        "the distinction between 'cannot receive a fix' and 'needs one' was lost")


def test_clean_lockfile_does_not_get_the_cve_disclaimer(tmp_path, capsys):
    """A project with no exposure should not be handed an irrelevant caveat."""
    from podfreeze.cli import main
    lock = tmp_path / "Podfile.lock"
    lock.write_text(
        "PODS:\n  - LocalKit (1.0)\n\nDEPENDENCIES:\n  - LocalKit\n\n"
        "SPEC REPOS:\n  https://github.internal.corp/Specs.git:\n    - LocalKit\n\n"
        "COCOAPODS: 1.15.2\n")
    main([str(lock)])
    out = capsys.readouterr().out
    assert "reports NO vulnerability data" not in out, (
        "clean projects should not receive the CVE disclaimer")


def test_swiftpm_unknown_is_not_stated_as_absent(tmp_path, monkeypatch):
    """78% of rows in a real audit could not resolve a Package.swift.

    Phrasing that as a property of the pod ("not at conventional path") invites the
    reader to conclude no SwiftPM migration route exists. The probe cannot support that
    claim: the trunk API exposes no source repository and the Specs CDN refuses
    automated requests, so it can only guess owner/name plus a small verified table.
    """
    from podfreeze import audit as audit_mod
    from podfreeze.enrich import Enrichment

    proj = tmp_path / "App"
    proj.mkdir()
    (proj / "Podfile.lock").write_text(
        "PODS:\n  - ObscurePod (1.0)\n\nDEPENDENCIES:\n  - ObscurePod\n\n"
        "SPEC REPOS:\n  trunk:\n    - ObscurePod\n\nCOCOAPODS: 1.15.2\n")

    monkeypatch.setattr(audit_mod, "enrich", lambda names, workers=8: [
        Enrichment(pod=n, latest_version="1.0", latest_published="2026-01-01",
                   total_versions=3, swiftpm_available=None) for n in names])
    md = audit_mod.render_markdown(audit_mod.run_audit(tmp_path), tmp_path)

    assert "not found — see note" in md, "the column no longer points at its caveat"
    assert "could not find a" in md and "not** that none exists" in md, (
        "the report no longer explains that an unresolved probe is not proof of absence")
    assert "Check the pod's own README" in md, (
        "the report no longer tells the reader how to settle it themselves")


def test_rate_limited_run_says_so(tmp_path, monkeypatch):
    """A rate-limited report must not look like a complete one.

    Unauthenticated GitHub search allows 10 requests per minute; a real audit needs far
    more. Without this, 58 rows read 'not found' because the probe could not run, and a
    buyer cannot tell that from a genuine negative.
    """
    from podfreeze import audit as audit_mod
    from podfreeze import enrich as en
    from podfreeze.enrich import Enrichment

    proj = tmp_path / "App"
    proj.mkdir()
    (proj / "Podfile.lock").write_text(
        "PODS:\n  - SomePod (1.0)\n\nDEPENDENCIES:\n  - SomePod\n\n"
        "SPEC REPOS:\n  trunk:\n    - SomePod\n\nCOCOAPODS: 1.15.2\n")
    monkeypatch.setattr(audit_mod, "enrich", lambda names, workers=8: [
        Enrichment(pod=n, latest_version="1.0", latest_published="2026-01-01",
                   total_versions=3, swiftpm_available=None) for n in names])

    en.SEARCH_BLOCKED["count"] = 0
    md_clean = audit_mod.render_markdown(audit_mod.run_audit(tmp_path), tmp_path)
    assert "rate-limited" not in md_clean.lower(), (
        "a clean run should not claim it was rate-limited")

    en.SEARCH_BLOCKED["count"] = 17
    try:
        md = audit_mod.render_markdown(audit_mod.run_audit(tmp_path), tmp_path)
        assert "This run was rate-limited" in md, (
            "a rate-limited run produces the same 'not found' as a real negative and "
            "must say so")
        assert "17" in md, "the report does not say how many lookups were refused"
        assert "GH_TOKEN" in md, "the report does not tell the reader how to fix it"
    finally:
        en.SEARCH_BLOCKED["count"] = 0


def test_rate_limit_counter_increments_only_on_throttling(monkeypatch):
    """A 404 is a verdict about the pod; a 403 is a verdict about the request."""
    import io
    import urllib.error
    from podfreeze import enrich as en

    for code, should_count in ((403, True), (429, True), (404, False), (500, False)):
        en.SEARCH_BLOCKED["count"] = 0
        def boom(req, *a, _c=code, **k):
            url = req.get_full_url() if hasattr(req, "get_full_url") else str(req)
            raise urllib.error.HTTPError(url, _c, "x", {}, io.BytesIO(b"{}"))
        monkeypatch.setattr(en.urllib.request, "urlopen", boom)
        en._search_swiftpm("AnyPod")
        got = en.SEARCH_BLOCKED["count"] > 0
        assert got is should_count, f"HTTP {code}: counted={got}, expected {should_count}"
    en.SEARCH_BLOCKED["count"] = 0


def test_head_probe_distinguishes_absence_from_inability(monkeypatch):
    """A 404 is a fact about the pod. A timeout is a fact about the network.

    _head_ok decides every 'SwiftPM: yes / not found' verdict. Returning False for an
    unreachable network turns "I could not look" into "there is no Package.swift" --
    on every row at once, which is exactly the silent-failure shape this tool exists to
    expose in other people's dependency trees.
    """
    import io
    import urllib.error
    from podfreeze import enrich as en

    cases = [
        (urllib.error.HTTPError("u", 404, "nf", {}, io.BytesIO(b"")), False),
        (urllib.error.HTTPError("u", 410, "gone", {}, io.BytesIO(b"")), False),
        (urllib.error.HTTPError("u", 403, "rl", {}, io.BytesIO(b"")), True),
        (urllib.error.HTTPError("u", 429, "rl", {}, io.BytesIO(b"")), True),
        (urllib.error.HTTPError("u", 500, "err", {}, io.BytesIO(b"")), True),
        (OSError("Network is unreachable"), True),
        (TimeoutError("timed out"), True),
    ]
    for exc, should_disclose in cases:
        en.SEARCH_BLOCKED["count"] = 0
        monkeypatch.setattr(
            en.urllib.request, "urlopen",
            lambda *a, _e=exc, **k: (_ for _ in ()).throw(_e))
        assert en._head_ok("https://example.invalid/Package.swift") is False
        disclosed = en.SEARCH_BLOCKED["count"] > 0
        assert disclosed is should_disclose, (
            f"{type(exc).__name__} {getattr(exc, 'code', '')}: disclosed={disclosed}, "
            f"expected {should_disclose}")
    en.SEARCH_BLOCKED["count"] = 0
