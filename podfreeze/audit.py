"""Organisation-wide audit — the tier priced for a buyer who has a budget.

A single developer scanning one Podfile.lock is a $29 problem. A company with 8 iOS
apps facing the 2 Dec 2026 trunk freeze has a different problem: which of our apps are
exposed, which pods are already dead, what order do we fix them in, and how much work
is it. That is a report a consultant would charge for, and it is what this produces.

Every number in the output is derived from data, never invented:
  - exposure comes from the lockfile's own SPEC REPOS section
  - staleness comes from the CocoaPods trunk API's published dates
  - migration targets come from probing for a real Package.swift
There are no invented effort hours, no made-up risk scores, no severity theatre.
"""
from __future__ import annotations

import datetime as _dt
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .analyse import FREEZE_DATE, analyse, vendor_cutoff
from .enrich import Enrichment, enrich
from .parser import ParseError, parse


@dataclass
class ProjectResult:
    path: Path
    name: str
    examined: int = 0
    exposed: list[str] = field(default_factory=list)
    insulated: int = 0
    unknown: int = 0
    error: str | None = None


@dataclass
class Audit:
    projects: list[ProjectResult] = field(default_factory=list)
    enrichment: dict[str, Enrichment] = field(default_factory=dict)

    @property
    def ok_projects(self) -> list[ProjectResult]:
        return [p for p in self.projects if not p.error]

    @property
    def failed_projects(self) -> list[ProjectResult]:
        return [p for p in self.projects if p.error]

    def pod_usage(self) -> dict[str, list[str]]:
        """Which projects depend on each exposed pod. Blast radius."""
        usage: dict[str, list[str]] = defaultdict(list)
        for p in self.ok_projects:
            for pod in p.exposed:
                usage[pod].append(p.name)
        return dict(usage)


def discover(root: Path, max_depth: int = 6) -> list[Path]:
    """Find every Podfile.lock under root. Skips vendored/build dirs."""
    skip = {"Pods", "node_modules", ".git", "build", "DerivedData", ".build",
            "Carthage", "vendor", ".venv"}
    found: list[Path] = []
    root = root.resolve()
    for p in root.rglob("Podfile.lock"):
        if any(part in skip for part in p.parts):
            continue
        if len(p.relative_to(root).parts) > max_depth:
            continue
        found.append(p)
    return sorted(found)


def run_audit(root: Path) -> Audit:
    audit = Audit()
    locks = discover(root)
    all_exposed: set[str] = set()

    for lock_path in locks:
        name = lock_path.parent.name or str(lock_path.parent)
        pr = ProjectResult(path=lock_path, name=name)
        try:
            lock = parse(lock_path.read_text(encoding="utf-8", errors="replace"))
        except (ParseError, OSError) as e:
            pr.error = str(e)
            audit.projects.append(pr)
            continue
        rep = analyse(lock)
        pr.examined = rep.examined
        pr.exposed = [f.pod.name for f in rep.exposed]
        pr.insulated = len(rep.insulated)
        pr.unknown = len([f for f in rep.findings if f.category == "unknown"])
        all_exposed.update(pr.exposed)
        audit.projects.append(pr)

    if all_exposed:
        audit.enrichment = {e.pod: e for e in enrich(sorted(all_exposed))}
    return audit


def _age_years(date_str: str | None) -> float | None:
    if not date_str:
        return None
    try:
        d = _dt.date.fromisoformat(date_str)
    except ValueError:
        return None
    return (_dt.date.today() - d).days / 365.25


def render_markdown(audit: Audit, root: Path) -> str:
    L: list[str] = []
    a = L.append
    today = _dt.date.today().isoformat()
    usage = audit.pod_usage()

    a(f"# CocoaPods trunk freeze — organisation audit")
    a("")
    a(f"Generated {today} by podfreeze. Scanned `{root}`.")
    a("")
    a(f"CocoaPods trunk goes permanently read-only on **{FREEZE_DATE}**, with a "
      f"read-only test run 1–7 November 2026. Source: "
      f"<https://blog.cocoapods.org/CocoaPods-Specs-Repo/>")
    a("")
    a("**Builds do not break.** Existing versions keep resolving from the Specs repo "
      "and the jsDelivr CDN. What changes is that an affected pod can never publish "
      "another version — including a security fix — to the coordinate you depend on.")
    a("")

    # --- Summary ---
    ok = audit.ok_projects
    exposed_projects = [p for p in ok if p.exposed]
    a("## Summary")
    a("")
    a(f"| | |")
    a(f"|---|---|")
    a(f"| Projects scanned | {len(ok)} |")
    a(f"| Projects with trunk exposure | {len(exposed_projects)} |")
    a(f"| Distinct exposed pods | {len(usage)} |")
    if audit.failed_projects:
        a(f"| Projects that could not be parsed | {len(audit.failed_projects)} |")
    a("")

    if not usage:
        a("No project in this tree resolves any pod from CocoaPods trunk. "
          "The freeze does not change how these projects receive updates.")
        a("")
        return "\n".join(L)

    # --- Vendor cutoffs that land BEFORE the trunk freeze ---
    early = sorted({p.split("/")[0] for p in usage if vendor_cutoff(p)})
    if early:
        a("## Earlier than the freeze — vendor publishing cutoffs")
        a("")
        a("These vendors stop publishing to CocoaPods **before** the trunk freeze. For "
          "any pod listed here, the vendor's date is your real deadline, not "
          f"{FREEZE_DATE}.")
        a("")
        a("| Pod | Vendor stops publishing | Projects affected |")
        a("|---|---|---|")
        for pod in early:
            n = len({proj for p, projects in usage.items()
                     for proj in projects if p.split("/")[0] == pod})
            a(f"| `{pod}` | **{vendor_cutoff(pod)}** | {n} |")
        a("")
        a("Source: <https://firebase.google.com/docs/ios/cocoapods-deprecation>")
        a("")

    # --- Priority order, evidence-based ---
    a("## What to deal with first")
    a("")
    a("Ranked by how long the pod has already been static — a pod that has not "
      "published in years is effectively frozen already, and the December date only "
      "makes that permanent. Blast radius is the number of your projects affected.")
    a("")
    a("| Pod | Last published | Static for | Your projects affected | SwiftPM target |")
    a("|---|---|---|---|---|")

    def sort_key(pod: str):
        e = audit.enrichment.get(pod)
        yrs = _age_years(e.latest_published) if e else None
        return (-(yrs or 0), -len(usage.get(pod, [])))

    for pod in sorted(usage, key=sort_key):
        e = audit.enrichment.get(pod)
        if e and e.latest_published:
            yrs = _age_years(e.latest_published)
            static = f"{yrs:.1f} years" if yrs else "—"
            pub = f"{e.latest_version} ({e.latest_published})"
        else:
            static = "unknown"
            pub = (e.error if e and e.error else "lookup failed")
        swift = "yes" if (e and e.swiftpm_available) else "not at conventional path"
        projects = usage[pod]
        shown = ", ".join(projects[:3]) + (f" +{len(projects)-3}" if len(projects) > 3 else "")
        a(f"| `{pod}` | {pub} | {static} | {len(projects)} — {shown} | {swift} |")
    a("")

    # --- Per project ---
    a("## By project")
    a("")
    for p in sorted(ok, key=lambda x: (-len(x.exposed), x.name)):
        a(f"### {p.name}")
        a("")
        a(f"`{p.path}`")
        a("")
        a(f"- examined **{p.examined}** pods")
        a(f"- **{len(p.exposed)}** resolve from trunk")
        a(f"- {p.insulated} already insulated (private spec repo, git or path pin)")
        if p.unknown:
            a(f"- {p.unknown} of undetermined source (lockfile predates CocoaPods 1.7)")
        if p.exposed:
            a("")
            a("  Exposed: " + ", ".join(f"`{x}`" for x in sorted(p.exposed)))
        a("")

    if audit.failed_projects:
        a("## Could not be parsed")
        a("")
        a("These files were found but could not be read as a Podfile.lock. They are "
          "reported rather than silently skipped, because a skipped file and a clean "
          "file must not look the same.")
        a("")
        for p in audit.failed_projects:
            a(f"- `{p.path}` — {p.error}")
        a("")

    a("## Method")
    a("")
    a("Exposure is read from each lockfile's own `SPEC REPOS:` section, so pods "
      "resolving from a private spec repo, or pinned to a git or path source, are "
      "reported as insulated rather than flagged. Publication dates come from the "
      "CocoaPods trunk API. SwiftPM availability is a probe for a real `Package.swift`.")
    a("")
    a("**No CVE data is included.** No vulnerability database covers the CocoaPods "
      "ecosystem: OSV.dev rejects `CocoaPods` as an invalid ecosystem and GitHub's "
      "advisory API returns 422 for `cocoapods`. A per-pod CVE lookup would return "
      "'no advisories' for everything — a broken join that looks identical to a clean "
      "result.")
    a("")
    return "\n".join(L)
