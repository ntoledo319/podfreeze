"""Issue templates are the support channel buyers are pointed at.

The Stripe confirmation and the storefront both promise a refund route through GitHub
issues. If a template is malformed, GitHub silently drops it from the chooser -- the
promise stays on the page while the mechanism behind it quietly stops working.

Nobody will be watching this repository closely after the operation that built it ends,
so the templates have to be right without supervision.
"""
from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = ROOT / ".github" / "ISSUE_TEMPLATE"

VALID_TYPES = {"markdown", "input", "textarea", "dropdown", "checkboxes"}


def _forms():
    return [p for p in sorted(TEMPLATE_DIR.glob("*.yml")) if p.name != "config.yml"]


def test_templates_exist():
    assert TEMPLATE_DIR.exists(), (
        "no issue templates — buyers are promised a refund route and get a blank box"
    )
    assert _forms(), "no issue forms present"


@pytest.mark.parametrize("path", _forms(), ids=lambda p: p.name)
def test_template_matches_githubs_schema(path):
    """A malformed form is dropped silently: the promise outlives the mechanism."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    for key in ("name", "description", "body"):
        assert key in data, f"{path.name}: missing required {key!r}"

    ids = []
    for i, el in enumerate(data["body"]):
        t = el.get("type")
        assert t in VALID_TYPES, f"{path.name}: body[{i}] invalid type {t!r}"
        if t == "markdown":
            assert el.get("attributes", {}).get("value"), (
                f"{path.name}: body[{i}] markdown block has no value")
            continue
        assert el.get("id"), f"{path.name}: body[{i}] ({t}) has no id"
        ids.append(el["id"])
        if t == "dropdown":
            assert el.get("attributes", {}).get("options"), (
                f"{path.name}: body[{i}] dropdown has no options")
    assert len(ids) == len(set(ids)), f"{path.name}: duplicate field ids {ids}"


def test_refund_promise_is_repeated_where_it_is_used():
    """The refund terms must appear at the point of asking, not only at the point of sale."""
    licence = TEMPLATE_DIR / "licence-or-refund.yml"
    assert licence.exists(), "no licence/refund template"
    text = licence.read_text(encoding="utf-8").lower()
    assert "no argument" in text and "no time limit" in text, (
        "the refund template no longer states the terms promised at checkout"
    )


def test_wrong_result_template_warns_against_pasting_private_lockfiles():
    """Asking for evidence must not invite a user to leak their own dependency tree."""
    form = TEMPLATE_DIR / "wrong-result.yml"
    assert form.exists(), "no wrong-result template"
    text = form.read_text(encoding="utf-8").lower()
    assert "do not paste a whole private lockfile" in text, (
        "the template no longer warns that issues are public"
    )


def test_config_links_point_at_live_pages():
    cfg = TEMPLATE_DIR / "config.yml"
    if not cfg.exists():
        pytest.skip("no config.yml")
    data = yaml.safe_load(cfg.read_text(encoding="utf-8"))
    for link in data.get("contact_links", []):
        for key in ("name", "url", "about"):
            assert key in link, f"contact link missing {key!r}"
        assert link["url"].startswith("https://"), f"insecure link {link['url']!r}"
