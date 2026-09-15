#!/usr/bin/env python3
"""Reproduce the podfreeze corpus findings from scratch.

The findings at https://ntoledo319.github.io/podfreeze/findings.html report that 96% of
real iOS projects whose dependency sources can be determined have at least one pod that
can never receive another published version after the CocoaPods trunk freeze.

Published measurements that cannot be re-run are just assertions with a table. This
script re-collects a corpus and re-derives every number, so anyone can check the claim
or measure their own sample.

It deliberately does NOT redistribute the corpus: lockfiles belong to their projects,
and the collection step fetches them fresh from public repositories.

Requires: the `gh` CLI, authenticated (`gh auth login`), and podfreeze installed.

    pip install "podfreeze @ git+https://github.com/ntoledo319/podfreeze@v0.5.2"
    python3 reproduce_findings.py --out results.json

Expect differences from the published run: GitHub code search results change over time,
and rate limits vary. A materially different exposure rate is worth reporting as an
issue -- that is the point of publishing this.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

QUERIES = [
    'filename:Podfile.lock "SPEC REPOS"',
    'filename:Podfile.lock Firebase',
    'filename:Podfile.lock "EXTERNAL SOURCES"',
    'filename:Podfile.lock React-Core',
    'filename:Podfile.lock "CHECKOUT OPTIONS"',
]

# Every spelling of the central specs index, normalised before comparison. Matching on
# literal strings caused a real false all-clear: a project using the URL without a .git
# suffix had every exposed pod reported as insulated.
TRUNK_ALIASES = {"trunk", "master", "github.com/cocoapods/specs", "cdn.cocoapods.org"}


def normalise_repo(value: str) -> str:
    v = value.strip().strip('"').strip("'").lower()
    v = re.sub(r"^[a-z0-9+.-]+://", "", v)
    v = re.sub(r"^git@([^:]+):", r"\1/", v)
    return re.sub(r"\.git$", "", v).rstrip("/")


def gh_json(args: list[str]) -> list:
    p = subprocess.run(["gh", *args], capture_output=True, text=True, timeout=90)
    if p.returncode != 0:
        return []
    out = p.stdout.strip()
    return [line for line in out.splitlines() if line.strip()]


def collect(limit: int) -> list[str]:
    repos: set[str] = set()
    for q in QUERIES:
        repos.update(gh_json(["api", "-X", "GET", "search/code", "-f", f"q={q}",
                              "-f", "per_page=30",
                              "-q", ".items[].repository.full_name"]))
        if len(repos) >= limit:
            break
    return sorted(repos)[:limit]


def fetch(repo: str, dest: Path) -> Path | None:
    p = subprocess.run(["gh", "api", f"repos/{repo}/contents/Podfile.lock",
                        "-q", ".content"], capture_output=True, text=True, timeout=45)
    if p.returncode != 0 or not p.stdout.strip():
        return None
    import base64
    try:
        raw = base64.b64decode(p.stdout)
    except Exception:  # noqa: BLE001
        return None
    if len(raw) < 50:
        return None
    path = dest / (repo.replace("/", "_") + ".lock")
    path.write_bytes(raw)
    return path


def raw_facts(text: str) -> tuple[set, set, bool]:
    """Re-derive counts from the raw file, independent of the scanner."""
    sec = re.search(r"^PODS:\n(.*?)(?=\n[A-Z][A-Z ]*:|\Z)", text, re.S | re.M)
    roots = set()
    if sec:
        for line in sec.group(1).splitlines():
            m = re.match(r'^  - "?([^\s("]+)', line)
            if m:
                roots.add(m.group(1).split("/")[0])
    trunk: set = set()
    sr = re.search(r"^SPEC REPOS:\n(.*?)(?=\n[A-Z][A-Z ]*:|\Z)", text, re.S | re.M)
    cur = None
    if sr:
        for line in sr.group(1).splitlines():
            rm = re.match(r'^  "?(\S.*?)"?:\s*$', line)
            if rm:
                cur = rm.group(1)
                continue
            em = re.match(r'^    - "?([^\s"]+)', line)
            if em and normalise_repo(cur or "") in TRUNK_ALIASES:
                trunk.add(em.group(1).split("/")[0])
    return roots, trunk, ("SPEC REPOS" in text)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=83, help="how many projects to sample")
    ap.add_argument("--out", default="reproduced-findings.json")
    args = ap.parse_args()

    if not shutil.which("gh"):
        print("needs the gh CLI: https://cli.github.com/", file=sys.stderr)
        return 2
    if not shutil.which("podfreeze"):
        print('needs podfreeze: pip install "podfreeze @ '
              'git+https://github.com/ntoledo319/podfreeze@v0.5.2"', file=sys.stderr)
        return 2

    tmp = Path(tempfile.mkdtemp(prefix="podfreeze-corpus-"))
    print(f"collecting up to {args.limit} projects...")
    repos = collect(args.limit)
    print(f"  {len(repos)} candidate repositories")

    stats, pod_counter, mismatches = [], Counter(), []
    for repo in repos:
        path = fetch(repo, tmp)
        if path is None:
            continue
        p = subprocess.run(["podfreeze", "--json", str(path)],
                           capture_output=True, text=True, timeout=60)
        if p.returncode != 0 or not p.stdout.strip().startswith("{"):
            continue
        d = json.loads(p.stdout)
        cats: dict[str, list] = {}
        for f in d["findings"]:
            cats.setdefault(f["category"], []).append(f["pod"].split("/")[0])
        for pod in cats.get("trunk", []):
            pod_counter[pod] += 1

        roots, trunk, has_sr = raw_facts(path.read_text(encoding="utf-8", errors="replace"))
        if d["examined"] != len(roots):
            mismatches.append(f"{repo}: examined {d['examined']} vs raw {len(roots)}")
        safe = set(cats.get("private-repo", [])) | set(cats.get("external", []))
        if trunk & safe:
            mismatches.append(f"{repo}: FALSE ALL-CLEAR on {sorted(trunk & safe)}")

        stats.append({"trunk": len(cats.get("trunk", [])),
                      "unknown": len(cats.get("unknown", []))})

    shutil.rmtree(tmp, ignore_errors=True)

    determinable = [s for s in stats if s["unknown"] == 0]
    det_exposed = [s for s in determinable if s["trunk"] > 0]
    counts = sorted(s["trunk"] for s in stats if s["trunk"] > 0)
    result = {
        "projects_examined": len(stats),
        "sources_determinable": len(determinable),
        "determinable_with_exposure": len(det_exposed),
        "determinable_exposure_pct": round(
            100 * len(det_exposed) / len(determinable), 1) if determinable else None,
        "median_exposed_pods": statistics.median(counts) if counts else 0,
        "most_common_exposed": pod_counter.most_common(15),
        "verification_mismatches": mismatches,
    }
    Path(args.out).write_text(json.dumps(result, indent=2))

    print(f"\n  projects examined            : {result['projects_examined']}")
    print(f"  sources determinable         : {result['sources_determinable']}")
    print(f"  of those, with exposure      : {result['determinable_with_exposure']}"
          f" ({result['determinable_exposure_pct']}%)")
    print(f"  median exposed pods          : {result['median_exposed_pods']}")
    print(f"  verification mismatches      : {len(mismatches)}")
    for m in mismatches[:5]:
        print(f"    {m}")
    print(f"\n  written to {args.out}")
    print("  published run: 83 examined, 57 determinable, 55 exposed (96.5%)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
