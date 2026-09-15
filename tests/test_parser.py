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
