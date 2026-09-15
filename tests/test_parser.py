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
