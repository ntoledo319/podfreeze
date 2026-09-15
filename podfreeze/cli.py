"""podfreeze CLI — CocoaPods trunk freeze exposure scanner.

Usage:
    podfreeze [PATH]            scan a Podfile.lock (default: ./Podfile.lock)
    podfreeze --json [PATH]     machine-readable output for CI
    podfreeze --pro [PATH]      migration plan (needs a licence key)
    podfreeze --audit DIR       scan every Podfile.lock in a tree (needs a licence key)
    podfreeze --version

On 2 December 2026 CocoaPods trunk stops accepting new podspecs. Your build does not
break — but pods resolving from trunk can never receive another published version,
including a security fix. This reports which of yours are affected.

Try it with no install: https://ntoledo319.github.io/podfreeze/check.html
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyse import FREEZE_DATE, TEST_RUN, Report, analyse
from .parser import ParseError, parse
from .pro import render_pro, verify_license

__version__ = "0.3.4"

SOURCE = "https://blog.cocoapods.org/CocoaPods-Specs-Repo/"


def _find_lockfile(given: str | None) -> Path:
    if given:
        p = Path(given)
        if p.is_dir():
            p = p / "Podfile.lock"
        return p
    return Path("Podfile.lock")


def render(rep: Report, path: Path) -> str:
    L: list[str] = []
    a = L.append
    a("")
    a(f"podfreeze {__version__} — CocoaPods trunk freeze exposure")
    a(f"file: {path}")
    if rep.cocoapods_version:
        a(f"lockfile written by CocoaPods {rep.cocoapods_version}")
    a("")
    # State what was EXAMINED, not only what was found. An empty result and a
    # silently-filtered one are otherwise indistinguishable.
    a(f"examined {rep.examined} pod(s)")
    if rep.spec_repo_names:
        a(f"spec repos declared: {', '.join(rep.spec_repo_names)}")
    a("")

    if not rep.spec_repos_section_present:
        a("  NOTE  This lockfile has no SPEC REPOS section (CocoaPods < 1.7).")
        a("        Pod sources cannot be determined exactly; they are reported as")
        a("        'unknown' rather than guessed. Run `pod install` with a modern")
        a("        CocoaPods to get an exact answer.")
        a("")

    exposed = rep.exposed
    if exposed:
        a(f"  {len(exposed)} pod(s) resolve from CocoaPods trunk:")
        a("")
        for f in exposed:
            ver = f" {f.pod.version}" if f.pod.version else ""
            a(f"    - {f.pod.name}{ver}")
        a("")
    ins = rep.insulated
    if ins:
        a(f"  {len(ins)} pod(s) already insulated from the freeze:")
        a("")
        for f in ins:
            a(f"    - {f.pod.name}: {f.reason}")
        a("")
    unknown = [f for f in rep.findings if f.category == "unknown"]
    if unknown:
        a(f"  {len(unknown)} pod(s) of undetermined source (see NOTE above)")
        a("")

    a("  WHAT THIS DOES AND DOES NOT MEAN")
    a("")
    a(f"  On {FREEZE_DATE} CocoaPods trunk stops accepting new podspecs.")
    a(f"  A read-only test run is scheduled for {TEST_RUN}.")
    a("")
    a("  Your build does NOT break. Existing versions keep resolving from the")
    a("  Specs repo on GitHub and the CDN on jsDelivr, so every Podfile that")
    a("  resolves today resolves the same way afterwards.")
    a("")
    if exposed:
        a("  What changes is that the pods listed above can never receive another")
        a("  PUBLISHED version on the coordinate you depend on — including a fix for")
        a("  a future security vulnerability. If one of them ships a CVE patch after")
        a("  the freeze, it cannot reach you through trunk; you would pin a git fork")
        a("  by hand.")
    else:
        a("  No pod in this lockfile resolves from trunk, so the freeze does not")
        a("  change how this project receives updates.")
    a("")
    a(f"  Source: {SOURCE}")
    a("")
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="podfreeze", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="?", help="Podfile.lock or directory containing one")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--pro", action="store_true",
                    help="migration plan for exposed pods (requires a licence key)")
    ap.add_argument("--audit", metavar="DIR",
                    help="scan every Podfile.lock under DIR and write an organisation "
                         "migration report (requires a licence key)")
    ap.add_argument("--out", metavar="FILE", default="podfreeze-audit.md",
                    help="where to write the audit report (default: podfreeze-audit.md)")
    ap.add_argument("--license", dest="license_key", default=None,
                    help="licence key (or set PODFREEZE_LICENSE)")
    ap.add_argument("--version", action="version", version=f"podfreeze {__version__}")
    args = ap.parse_args(argv)

    # --- Organisation audit (licensed) -------------------------------------
    if args.audit:
        from pathlib import Path as _P

        from .audit import render_markdown, run_audit

        if not verify_license(args.license_key):
            print("podfreeze: --audit requires a licence key.", file=sys.stderr)
            print("  Set PODFREEZE_LICENSE or pass --license.", file=sys.stderr)
            print("  https://github.com/ntoledo319/podfreeze#pro", file=sys.stderr)
            return 4
        root = _P(args.audit)
        if not root.is_dir():
            print(f"podfreeze: not a directory: {root}", file=sys.stderr)
            return 2
        audit_result = run_audit(root)
        n_locks = len(audit_result.projects)
        if n_locks == 0:
            print(f"podfreeze: no Podfile.lock found anywhere under {root}",
                  file=sys.stderr)
            return 5
        md = render_markdown(audit_result, root)
        out = _P(args.out)
        out.write_text(md, encoding="utf-8")
        exposed_projects = [p for p in audit_result.ok_projects if p.exposed]
        print(f"podfreeze audit: scanned {n_locks} Podfile.lock file(s) under {root}")
        print(f"  {len(exposed_projects)} project(s) with trunk exposure")
        print(f"  {len(audit_result.pod_usage())} distinct exposed pod(s)")
        if audit_result.failed_projects:
            print(f"  {len(audit_result.failed_projects)} file(s) could not be parsed "
                  f"(listed in the report, not silently skipped)")
        print(f"  report written to {out}")
        return 0

    path = _find_lockfile(args.path)
    if not path.exists():
        # The most common first-run mistake. Be useful, and exit non-zero so a script
        # never reads "no lockfile here" as "nothing to worry about".
        print(f"podfreeze: no Podfile.lock found at {path}", file=sys.stderr)
        print("", file=sys.stderr)
        print("  Run it from a directory containing a Podfile.lock, or pass a path:",
              file=sys.stderr)
        print("    podfreeze path/to/Podfile.lock", file=sys.stderr)
        print("    podfreeze path/to/project/", file=sys.stderr)
        print("", file=sys.stderr)
        print("  No install needed either — paste your lockfile at:", file=sys.stderr)
        print("    https://ntoledo319.github.io/podfreeze/check.html", file=sys.stderr)
        return 2
    try:
        lock = parse(path.read_text(encoding="utf-8", errors="replace"))
    except ParseError as e:
        # Loud failure. Never report "clean" because parsing failed.
        print(f"podfreeze: could not parse {path}: {e}", file=sys.stderr)
        return 3

    rep = analyse(lock)
    if args.json:
        print(json.dumps({
            "version": __version__,
            "file": str(path),
            "freeze_date": FREEZE_DATE,
            "test_run": TEST_RUN,
            "examined": rep.examined,
            "counts": rep.counts(),
            "spec_repos": rep.spec_repo_names,
            "spec_repos_section_present": rep.spec_repos_section_present,
            "findings": [
                {"pod": f.pod.name, "version": f.pod.version,
                 "category": f.category, "reason": f.reason}
                for f in rep.findings
            ],
            "source": SOURCE,
        }, indent=2))
    else:
        print(render(rep, path))
        if args.pro:
            print(render_pro(rep, verify_license(args.license_key)))
        elif rep.exposed:
            print(render_pro(rep, licensed=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
