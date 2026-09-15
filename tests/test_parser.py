"""Tests for podfreeze. Run: python3 -m pytest podfreeze/tests -q

Includes a CENSUS test that pins the exact expected finding set. Per-parser tests
passing individually do not catch a change that silently drops one input form -- the run
still exits zero and still names real findings, and the loss is invisible. The census
fails both when a form disappears (naming which) and when an unreviewed one appears.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from podfreeze.analyse import analyse                      # noqa: E402
from podfreeze.parser import ParseError, parse             # noqa: E402
from tests import fixtures as fx                           # noqa: E402


# --------------------------------------------------------------------------
# Parse failures must RAISE, never return an empty "clean" result.
# A scanner that swallows a parse error reports "nothing found", which is
# byte-identical to a passing result and ships silently.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("text,label", [
    (fx.EMPTY, "empty file"),
    (fx.NOT_A_LOCKFILE, "valid YAML but not a lockfile"),
    (fx.MALFORMED_YAML, "malformed YAML"),
])
def test_bad_input_raises_not_silently_clean(text, label):
    with pytest.raises(ParseError):
        parse(text)


def test_parses_versions_and_subspecs():
    lock = parse(fx.MIXED)
    names = {p.name for p in lock.roots()}
    assert names == {"Alamofire", "SDWebImage", "InternalAuth", "LocalKit"}
    sd = next(p for p in lock.roots() if p.name == "SDWebImage")
    assert sd.version == "5.18.10"
    # Subspec must fold into its root, not appear as a separate package.
    assert "SDWebImage/Core" not in names


def test_private_spec_repo_is_not_trunk():
    rep = analyse(parse(fx.MIXED))
    internal = next(f for f in rep.findings if f.pod.name == "InternalAuth")
    assert internal.category == "private-repo"


def test_external_source_is_not_trunk():
    rep = analyse(parse(fx.MIXED))
    local = next(f for f in rep.findings if f.pod.name == "LocalKit")
    assert local.category == "external"


def test_trunk_pods_are_flagged():
    rep = analyse(parse(fx.MIXED))
    assert {f.pod.name for f in rep.exposed} == {"Alamofire", "SDWebImage"}


def test_cdn_key_counts_as_trunk():
    """The CDN URL is a trunk alias; missing it would under-report exposure."""
    rep = analyse(parse(fx.CDN_KEY))
    assert [f.pod.name for f in rep.exposed] == ["Realm"]


def test_fully_insulated_reports_zero_exposure():
    """The result that must never be a false alarm."""
    rep = analyse(parse(fx.FULLY_INSULATED))
    assert rep.exposed == []
    assert len(rep.insulated) == 2


def test_legacy_lockfile_marked_unknown_not_trunk():
    """Pre-1.7 lockfiles have no SPEC REPOS; must be 'unknown', not asserted trunk."""
    rep = analyse(parse(fx.LEGACY_NO_SPEC_REPOS))
    assert {f.category for f in rep.findings} == {"unknown"}
    assert rep.spec_repos_section_present is False


# --------------------------------------------------------------------------
# CENSUS — pins the EXACT finding set across every input form at once.
# --------------------------------------------------------------------------
EXPECTED_CENSUS = {
    ("Alamofire", "trunk"),
    ("SDWebImage", "trunk"),
    ("InternalAuth", "private-repo"),
    ("LocalKit", "external"),
}


def test_census_exact_finding_set():
    rep = analyse(parse(fx.MIXED))
    actual = {(f.pod.name, f.category) for f in rep.findings}
    missing = EXPECTED_CENSUS - actual
    unexpected = actual - EXPECTED_CENSUS
    assert not missing, f"DETECTION LOST for: {sorted(missing)}"
    assert not unexpected, f"UNREVIEWED new detections: {sorted(unexpected)}"


def test_report_states_what_it_examined_not_only_what_it_found():
    """An empty result and a silently-filtered one are the same bytes without this."""
    rep = analyse(parse(fx.FULLY_INSULATED))
    assert rep.examined == 2          # examined 2 even though 0 are exposed
    assert rep.exposed == []


# --- Organisation audit (v0.3.0) ------------------------------------------
def test_audit_discovers_and_classifies_multiple_projects(tmp_path):
    """The $499 tier's core claim: scan a whole tree, get per-project truth."""
    from podfreeze.audit import run_audit
    (tmp_path / "app-a").mkdir()
    (tmp_path / "app-b").mkdir()
    (tmp_path / "app-a" / "Podfile.lock").write_text(fx.MIXED)
    (tmp_path / "app-b" / "Podfile.lock").write_text(fx.FULLY_INSULATED)
    a = run_audit(tmp_path)
    assert len(a.ok_projects) == 2
    usage = a.pod_usage()
    assert set(usage) == {"Alamofire", "SDWebImage"}
    assert usage["Alamofire"] == ["app-a"]


def test_audit_skips_vendored_pods_dir(tmp_path):
    """A Pods/ dir contains a copy; counting it would double-report."""
    from podfreeze.audit import discover
    (tmp_path / "Pods").mkdir()
    (tmp_path / "Pods" / "Podfile.lock").write_text(fx.MIXED)
    (tmp_path / "Podfile.lock").write_text(fx.MIXED)
    assert len(discover(tmp_path)) == 1


def test_audit_reports_unparseable_files_instead_of_skipping(tmp_path):
    """A skipped file and a clean file must never look the same."""
    from podfreeze.audit import run_audit
    (tmp_path / "broken").mkdir()
    (tmp_path / "broken" / "Podfile.lock").write_text(fx.NOT_A_LOCKFILE)
    a = run_audit(tmp_path)
    assert len(a.failed_projects) == 1
    assert a.ok_projects == []


# --- Edge cases found by adversarial fixture testing (loop #12) -------------
AMBIGUOUS_SOURCE = """
PODS:
  - Shared (1.0.0)

DEPENDENCIES:
  - Shared

SPEC REPOS:
  https://internal.example/Specs.git:
    - Shared
  trunk:
    - Shared

COCOAPODS: 1.15.2
"""

REAL_QUOTED = """
PODS:
  - "Ünïcödé-Pod (1.0.0)"
  - "GoogleUtilities/Environment (7.11.0)"
  - pod.with.dots (2.0.0)

DEPENDENCIES:
  - pod.with.dots

SPEC REPOS:
  trunk:
    - "Ünïcödé-Pod"
    - GoogleUtilities
    - pod.with.dots

COCOAPODS: 1.15.2
"""

CRLF = ("PODS:\r\n  - Alamofire (5.8.1)\r\n\r\nDEPENDENCIES:\r\n  - Alamofire\r\n\r\n"
        "SPEC REPOS:\r\n  trunk:\r\n    - Alamofire\r\n\r\nCOCOAPODS: 1.15.2\r\n")

BOM = "\ufeffPODS:\n  - Alamofire (5.8.1)\n\nSPEC REPOS:\n  trunk:\n    - Alamofire\n"

WITH_CHECKSUMS = """
PODS:
  - Alamofire (5.8.1)

SPEC REPOS:
  trunk:
    - Alamofire

SPEC CHECKSUMS:
  Alamofire: 3ca42e259043ee0dc5c0cdd76c4bc568b8e42af7

PODFILE CHECKSUM: 8d2f1a9e0b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e

COCOAPODS: 1.15.2
"""


def test_pod_under_two_spec_repos_resolves_to_trunk():
    """SECURITY-RELEVANT: ambiguity must resolve toward exposed, never toward safe.

    Before the fix the last repo listed won, so a pod under both trunk and a private
    repo was reported INSULATED — silently under-reporting real exposure.
    """
    rep = analyse(parse(AMBIGUOUS_SOURCE))
    assert [f.pod.name for f in rep.exposed] == ["Shared"], \
        "a pod sourced from trunk anywhere must be reported as exposed"


def test_real_cocoapods_quoting_and_unicode():
    """CocoaPods quotes the whole scalar: - "Name (1.0.0)" — not just the name."""
    rep = analyse(parse(REAL_QUOTED))
    names = {f.pod.name for f in rep.findings}
    assert "Ünïcödé-Pod" in names
    assert "pod.with.dots" in names
    assert "GoogleUtilities" in names      # subspec folded to root


def test_crlf_and_bom_and_trailing_sections():
    for label, text in (("crlf", CRLF), ("bom", BOM), ("checksums", WITH_CHECKSUMS)):
        rep = analyse(parse(text))
        assert [f.pod.name for f in rep.exposed] == ["Alamofire"], f"{label} failed"


# --- Buyer-facing failure modes (loop #14) ---------------------------------
def test_licence_key_tolerates_real_paste_behaviour():
    """A paying buyer must not be locked out by whitespace or case."""
    from podfreeze.pro import verify_license
    good = "PDFZ1-O110FBF11EE4-69DEE505AB1993B2"
    assert verify_license(good)
    assert verify_license(f"  {good}  "), "stray whitespace locked out a paying buyer"
    assert verify_license(good.lower()), "lowercase key locked out a paying buyer"
    assert not verify_license("garbage")
    assert not verify_license("")
    assert not verify_license("PDFZ1-short-x")


def test_network_failure_is_not_reported_as_a_finding(monkeypatch):
    """An outage must say 'lookup could not run', never 'not found on trunk'.

    Conflating them tells a user their pod is absent from trunk when in fact
    nothing was checked - a false statement about their dependency.
    """
    from podfreeze import enrich as en
    monkeypatch.setattr(en, "_get", lambda url: None)
    monkeypatch.setattr(en, "_NET_STATE", False, raising=False)
    _, _, _, err = en.fetch_trunk("Alamofire")
    assert "NETWORK UNAVAILABLE" in err
    assert "not found" not in err.lower()


def test_truncated_file_is_an_error_not_a_legacy_lockfile():
    """A cut-short paste must NOT be reported as 'legacy, sources unknown'.

    Found by driving the real browser UI: pasting a truncated lockfile produced a
    clean-looking Result claiming 'your build does not break'. Both the Python and JS
    parsers agreed - and both were wrong the same way, which is exactly what a
    cross-implementation check cannot catch.
    """
    with pytest.raises(ParseError, match="truncated"):
        parse("PODS:\n  - Alam")
    # A genuine legacy lockfile (no SPEC REPOS but complete) must still parse.
    rep = analyse(parse(fx.LEGACY_NO_SPEC_REPOS))
    assert rep.examined == 2


def test_missing_lockfile_exits_nonzero_with_guidance(tmp_path, capsys, monkeypatch):
    """Exit 0 on 'no lockfile found' would let CI read absence as 'all clear'."""
    from podfreeze.cli import main
    monkeypatch.chdir(tmp_path)
    rc = main([])
    assert rc == 2, "missing lockfile must exit non-zero"
    err = capsys.readouterr().err
    assert "no Podfile.lock found" in err
    assert "check.html" in err, "should offer the zero-install route"


def test_firebase_vendor_cutoff_is_surfaced(tmp_path, capsys):
    """Firebase stops publishing Oct 2026 - EARLIER than the trunk freeze.

    A user with Firebase who only hears '2 Dec' gets a date that is two months late.
    """
    from podfreeze.cli import main
    lock = tmp_path / "Podfile.lock"
    lock.write_text(
        "PODS:\n  - FirebaseAuth (10.0.0)\n  - Alamofire (5.8.1)\n\n"
        "DEPENDENCIES:\n  - FirebaseAuth\n  - Alamofire\n\n"
        "SPEC REPOS:\n  trunk:\n    - FirebaseAuth\n    - Alamofire\n\n"
        "COCOAPODS: 1.15.2\n"
    )
    main([str(lock)])
    out = capsys.readouterr().out
    assert "EARLIER DEADLINE" in out
    assert "FirebaseAuth" in out
    assert "2026-10" in out


def test_no_firebase_means_no_earlier_deadline_noise(tmp_path, capsys):
    """Projects without affected vendors must not see an irrelevant warning."""
    from podfreeze.cli import main
    lock = tmp_path / "Podfile.lock"
    lock.write_text(
        "PODS:\n  - Alamofire (5.8.1)\n\nDEPENDENCIES:\n  - Alamofire\n\n"
        "SPEC REPOS:\n  trunk:\n    - Alamofire\n\nCOCOAPODS: 1.15.2\n"
    )
    main([str(lock)])
    assert "EARLIER DEADLINE" not in capsys.readouterr().out


def test_paid_audit_reports_vendor_cutoffs(tmp_path):
    """The $499 report must not be BEHIND the free CLI on vendor deadlines."""
    from podfreeze.audit import run_audit, render_markdown
    proj = tmp_path / "AppA"
    proj.mkdir()
    (proj / "Podfile.lock").write_text(
        "PODS:\n  - FirebaseAuth (10.0.0)\n\nDEPENDENCIES:\n  - FirebaseAuth\n\n"
        "SPEC REPOS:\n  trunk:\n    - FirebaseAuth\n\nCOCOAPODS: 1.15.2\n"
    )
    md = render_markdown(run_audit(tmp_path), tmp_path)
    assert "Earlier than the freeze" in md
    assert "FirebaseAuth" in md
    assert "2026-10" in md


def test_paid_audit_silent_without_affected_vendors(tmp_path):
    from podfreeze.audit import run_audit, render_markdown
    proj = tmp_path / "AppB"
    proj.mkdir()
    (proj / "Podfile.lock").write_text(
        "PODS:\n  - Alamofire (5.8.1)\n\nDEPENDENCIES:\n  - Alamofire\n\n"
        "SPEC REPOS:\n  trunk:\n    - Alamofire\n\nCOCOAPODS: 1.15.2\n"
    )
    md = render_markdown(run_audit(tmp_path), tmp_path)
    assert "Earlier than the freeze" not in md


REAL_RN_LOCK = """PODS:
  - Alamofire (5.8.1)
  - React-Core (0.72.6):
    - glog
    - RCT-Folly (= 2021.07.22.00)
    - React-Core/Default (= 0.72.6)
  - React-Core/Default (0.72.6):
    - glog
  - FirebaseAuth (10.18.0):
    - FirebaseCore (~> 10.0)
  - glog (0.3.5)

DEPENDENCIES:
  - React-Core (from `../node_modules/react-native/`)
  - FirebaseAuth
  - Alamofire

SPEC REPOS:
  trunk:
    - Alamofire
    - FirebaseAuth
    - glog

EXTERNAL SOURCES:
  React-Core:
    :path: "../node_modules/react-native/"

SPEC CHECKSUMS:
  Alamofire: 3ca42e259043ee0dc5c0cdd76c4bc568b8e42af7

COCOAPODS: 1.15.2
"""


def test_real_react_native_lockfile_shape(tmp_path, capsys):
    """Nested deps with colons are the COMMON real-world shape, not an edge case.

    A React Native Podfile.lock is what a large share of real iOS projects actually
    have. If this shape breaks, the tool is useless to most of its audience.
    """
    from podfreeze.cli import main
    lock = tmp_path / "Podfile.lock"
    lock.write_text(REAL_RN_LOCK)
    assert main([str(lock)]) == 0
    out = capsys.readouterr().out
    assert "Alamofire" in out and "FirebaseAuth" in out and "glog" in out
    # React-Core is pinned via EXTERNAL SOURCES and must NOT be called exposed
    assert "EXTERNAL SOURCES" in out or "insulated" in out
    # the vendor cutoff must still surface through a nested entry
    assert "EARLIER DEADLINE" in out


def test_subspec_resolves_to_parent_vendor(tmp_path, capsys):
    """FirebaseFirestore/Swift must inherit FirebaseFirestore's cutoff."""
    from podfreeze.cli import main
    lock = tmp_path / "Podfile.lock"
    lock.write_text(
        "PODS:\n  - FirebaseFirestore/Swift (10.18.0)\n\n"
        "DEPENDENCIES:\n  - FirebaseFirestore/Swift\n\n"
        "SPEC REPOS:\n  trunk:\n    - FirebaseFirestore\n\nCOCOAPODS: 1.15.2\n"
    )
    main([str(lock)])
    assert "EARLIER DEADLINE" in capsys.readouterr().out


def test_malformed_entry_refuses_rather_than_guesses(tmp_path):
    """A pod line the parser cannot read must FAIL, never be silently dropped."""
    from podfreeze.cli import main
    lock = tmp_path / "Podfile.lock"
    lock.write_text(
        "PODS:\n  - React-Core (0.0.0) - React-Core/Core (= 0.0.0)\n\n"
        "DEPENDENCIES:\n  - React-Core\n\nSPEC REPOS:\n  trunk:\n    - React-Core\n\n"
        "COCOAPODS: 1.15.2\n"
    )
    assert main([str(lock)]) == 3, "unparseable input must exit non-zero, not report clean"


def test_priority_ranks_actively_published_pods_first(tmp_path, monkeypatch):
    """A pod still publishing loses a live channel; a dead pod loses nothing.

    Ranking stalest-first told buyers to migrate abandoned libraries before the ones
    actually shipping security fixes -- backwards advice in the section titled
    'What to deal with first'.
    """
    from podfreeze import audit as audit_mod
    from podfreeze.enrich import Enrichment

    proj = tmp_path / "App"
    proj.mkdir()
    (proj / "Podfile.lock").write_text(
        "PODS:\n  - AncientPod (1.0)\n  - ActivePod (9.0)\n\n"
        "DEPENDENCIES:\n  - AncientPod\n  - ActivePod\n\n"
        "SPEC REPOS:\n  trunk:\n    - AncientPod\n    - ActivePod\n\nCOCOAPODS: 1.15.2\n"
    )

    def fake_enrich(names, workers=8):
        out = []
        for n in names:
            if n == "AncientPod":
                out.append(Enrichment(pod=n, latest_version="1.0",
                                      latest_published="2017-01-01", total_versions=3))
            else:
                out.append(Enrichment(pod=n, latest_version="9.0",
                                      latest_published="2026-05-05", total_versions=40))
        return out

    monkeypatch.setattr(audit_mod, "enrich", fake_enrich)
    md = audit_mod.render_markdown(audit_mod.run_audit(tmp_path), tmp_path)

    body = md.split("## What to deal with first", 1)[1]
    active_at = body.index("ActivePod")
    ancient_at = body.index("AncientPod")
    assert active_at < ancient_at, (
        "the actively-published pod must rank first -- it is the one losing a live "
        "update channel at the freeze"
    )
