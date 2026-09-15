"""Documentation must describe the action that actually exists.

A copy-pasteable YAML example is a promise. If the README names an input the action
does not accept, the user's workflow fails with a confusing error and the docs are
worse than no docs at all.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
ACTION = ROOT / "action.yml"


def _action():
    return yaml.safe_load(ACTION.read_text(encoding="utf-8"))


def test_documented_inputs_all_exist():
    rd = README.read_text(encoding="utf-8")
    real = set(_action().get("inputs", {}))
    documented = set(re.findall(r"^\| `([a-z-]+)` \|", rd, re.M))
    assert documented, "README documents no action inputs at all"
    assert documented <= real, (
        f"README documents inputs the action does not accept: {sorted(documented - real)}"
    )


def test_documented_outputs_all_exist():
    rd = README.read_text(encoding="utf-8")
    real = set(_action().get("outputs", {}))
    m = re.search(r"Outputs: (.+?)\.?$", rd, re.M)
    assert m, "README does not document the action outputs"
    documented = {o.strip().strip("`.") for o in m.group(1).split(",")}
    assert documented <= real, (
        f"README documents outputs the action does not emit: {sorted(documented - real)}"
    )


def test_readme_yaml_examples_parse():
    """A workflow example that is not valid YAML cannot be copy-pasted."""
    rd = README.read_text(encoding="utf-8")
    blocks = re.findall(r"```yaml\n(.*?)```", rd, re.S)
    assert blocks, "README has no YAML workflow example"
    for i, block in enumerate(blocks, 1):
        yaml.safe_load(block)  # raises on malformed YAML


def test_readme_pins_the_action_to_a_tag():
    """`uses: ...@main` in docs would hand users a moving, unprotected target."""
    rd = README.read_text(encoding="utf-8")
    uses = re.findall(r"uses: ntoledo319/podfreeze@(\S+)", rd)
    assert uses, "README never shows how to reference the action"
    for ref in uses:
        assert ref.startswith("v"), f"action example uses a moving ref: @{ref}"
