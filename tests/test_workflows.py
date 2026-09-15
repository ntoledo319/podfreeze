"""Verification workflows must fire without a human remembering.

consumer-sim.yml is the only thing that exercises the GitHub Action the way an external
consumer does. It was workflow_dispatch-only and went ~20 commits without running --
across a parser change and a ranking change -- while every other signal stayed green.

A check that only runs when remembered is not a check.
"""
from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# Workflows that must fire automatically.
MUST_BE_AUTOMATIC = {"test.yml", "consumer-sim.yml"}

# Deliberately on-demand, with the reason recorded.
MANUAL_OK = {
    "install-matrix.yml": "also fires on release: published",
    "pr-comment-sim.yml": "would comment on every PR; verified on demand",
}


def _triggers(path: Path) -> set:
    yaml_mod = pytest.importorskip("yaml")
    data = yaml_mod.safe_load(path.read_text(encoding="utf-8"))
    # PyYAML parses the bare key `on:` as the boolean True
    raw = data.get("on") if "on" in data else data.get(True)
    if isinstance(raw, dict):
        return set(raw)
    if isinstance(raw, list):
        return set(raw)
    return {raw} if raw else set()


def test_workflows_directory_exists():
    wf = ROOT / ".github" / "workflows"
    assert wf.exists(), "no workflows directory — CI protects nothing"
    assert list(wf.glob("*.yml")), "workflows directory is empty"


@pytest.mark.parametrize("name", sorted(MUST_BE_AUTOMATIC))
def test_critical_workflow_runs_without_being_asked(name):
    path = ROOT / ".github" / "workflows" / name
    if not path.exists():
        pytest.skip(f"{name} not present in this tree")
    names = _triggers(path)
    assert names & {"push", "pull_request", "schedule"}, (
        f"{name} only runs on {sorted(names)} — it stops protecting anything the "
        f"moment nobody remembers to dispatch it"
    )


def test_every_workflow_is_automatic_or_explicitly_manual():
    wf_dir = ROOT / ".github" / "workflows"
    for path in sorted(wf_dir.glob("*.yml")):
        names = _triggers(path)
        if path.name in MANUAL_OK:
            continue
        assert names & {"push", "pull_request", "schedule", "release"}, (
            f"{path.name} has no automatic trigger and is not recorded in MANUAL_OK "
            f"with a reason"
        )
