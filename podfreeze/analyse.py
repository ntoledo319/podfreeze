"""Trunk-freeze exposure analysis.

WHAT THIS TOOL CLAIMS, PRECISELY
--------------------------------
On 2 December 2026 CocoaPods trunk stops accepting new podspecs. Per the maintainer's
announcement, existing builds KEEP RESOLVING -- the Specs repo on GitHub and the CDN on
jsDelivr continue to serve. This tool therefore does NOT claim your build breaks.

What it reports is narrower and real: which of your pods are pinned to coordinates that
can never receive another published version -- including a security patch -- after the
freeze, and which are already insulated because they resolve from a private spec repo,
a git source, or a vendored path.
"""
from __future__ import annotations

from dataclasses import dataclass

from .parser import Lockfile, Pod

FREEZE_DATE = "2026-12-02"
TEST_RUN = "2026-11-01 to 2026-11-07"


@dataclass
class Finding:
    pod: Pod
    category: str          # "trunk" | "private-repo" | "external" | "unknown"
    reason: str


@dataclass
class Report:
    findings: list[Finding]
    examined: int
    cocoapods_version: str | None
    spec_repos_section_present: bool
    spec_repo_names: list[str]

    @property
    def exposed(self) -> list[Finding]:
        return [f for f in self.findings if f.category == "trunk"]

    @property
    def insulated(self) -> list[Finding]:
        return [f for f in self.findings if f.category in ("private-repo", "external")]

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.category] = out.get(f.category, 0) + 1
        return out


def analyse(lock: Lockfile) -> Report:
    findings: list[Finding] = []
    for pod in lock.roots():
        if pod.external_source:
            kind = ", ".join(sorted(k for k in pod.external_source if k != "raw")) or "external"
            findings.append(Finding(pod, "external",
                                    f"pinned via EXTERNAL SOURCES ({kind}); bypasses trunk"))
        elif pod.spec_repo and not pod.from_trunk:
            findings.append(Finding(pod, "private-repo",
                                    f"resolves from private spec repo {pod.spec_repo}"))
        elif pod.spec_repo is None and not lock.spec_repos_section_present:
            findings.append(Finding(pod, "unknown",
                                    "no SPEC REPOS section in lockfile (CocoaPods < 1.7); "
                                    "source inferred as the central specs repo"))
        else:
            findings.append(Finding(pod, "trunk",
                                    "resolves from CocoaPods trunk; no future version "
                                    "can be published after the freeze"))
    return Report(
        findings=findings,
        examined=len(lock.roots()),
        cocoapods_version=lock.cocoapods_version,
        spec_repos_section_present=lock.spec_repos_section_present,
        spec_repo_names=sorted(lock.spec_repos.keys()),
    )
