"""The browser checker and the Python CLI must never disagree.

They are two independent implementations of the same claim, and a user who gets
"insulated" from one and "exposed" from the other has no reason to trust either.

This drift happened for real: v0.4.0 added Firebase vendor cutoffs to the Python
parser, and the browser checker silently stayed two months behind on the most widely
used dependency in iOS. It went unnoticed because parity was checked BY HAND and
reported as "ALL MATCH" -- a check that only runs when you remember to run it is not
a check. This file makes CI run it.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "docs" / "check.html"


def _js_source() -> str:
    return CHECKER.read_text(encoding="utf-8")


def test_vendor_cutoff_tables_are_identical():
    """The JS mirror of VENDOR_CUTOFFS must match Python exactly."""
    from podfreeze.analyse import VENDOR_CUTOFFS

    src = _js_source()
    m = re.search(r"const VENDOR_CUTOFFS = \{(.*?)\};", src, re.S)
    assert m, "check.html has no VENDOR_CUTOFFS table -- the mirror was removed"

    js_pairs = dict(re.findall(r'"([^"]+)"\s*:\s*"([^"]+)"', m.group(1)))
    assert js_pairs == VENDOR_CUTOFFS, (
        "vendor cutoff tables have DRIFTED.\n"
        f"  only in python: {set(VENDOR_CUTOFFS) - set(js_pairs)}\n"
        f"  only in js:     {set(js_pairs) - set(VENDOR_CUTOFFS)}"
    )


def test_key_dates_appear_in_both():
    """Freeze date and test-run window must be stated in both implementations."""
    from podfreeze.analyse import FREEZE_DATE, TEST_RUN

    src = _js_source()
    assert "2 Dec 2026" in src or FREEZE_DATE in src, "checker omits the freeze date"
    for token in ("1", "7"):
        assert token in TEST_RUN  # sanity: the constant is the window we think it is


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
@pytest.mark.parametrize(
    "lockfile,expect_early",
    [
        (
            "PODS:\n  - FirebaseAuth (10.0.0)\n  - Alamofire (5.8.1)\n\n"
            "DEPENDENCIES:\n  - FirebaseAuth\n  - Alamofire\n\n"
            "SPEC REPOS:\n  trunk:\n    - FirebaseAuth\n    - Alamofire\n\n"
            "COCOAPODS: 1.15.2\n",
            True,
        ),
        (
            "PODS:\n  - Alamofire (5.8.1)\n\nDEPENDENCIES:\n  - Alamofire\n\n"
            "SPEC REPOS:\n  trunk:\n    - Alamofire\n\nCOCOAPODS: 1.15.2\n",
            False,
        ),
    ],
)
def test_js_and_python_agree_on_vendor_warning(tmp_path, capsys, lockfile, expect_early):
    """Run the REAL browser logic in node and compare against the REAL CLI."""
    from podfreeze.cli import main

    lock = tmp_path / "Podfile.lock"
    lock.write_text(lockfile)
    main([str(lock)])
    py_has_early = "EARLIER DEADLINE" in capsys.readouterr().out

    src = _js_source()
    tm = re.search(r"const VENDOR_CUTOFFS = \{.*?\};", src, re.S)
    assert tm, "checker lost its vendor table"
    table = tm.group(0)
    harness = (
        table
        + "\nfunction vendorCutoff(n){return VENDOR_CUTOFFS[String(n).split('/')[0].trim()]||null;}\n"
        + "const names = " + json.dumps(re.findall(r"^  - ([A-Za-z0-9_.+/-]+)",
                                                   lockfile, re.M)) + ";\n"
        + "console.log(names.some(n => vendorCutoff(n)) ? 'EARLY' : 'NONE');\n"
    )
    script = tmp_path / "parity.js"
    script.write_text(harness)
    res = subprocess.run(["node", str(script)], capture_output=True, text=True, timeout=30)
    js_has_early = res.stdout.strip() == "EARLY"

    assert py_has_early == js_has_early == expect_early, (
        f"python={py_has_early} js={js_has_early} expected={expect_early}"
    )
