"""Podfile.lock parsing.

Podfile.lock is YAML, but its meaning is not obvious from the YAML alone. The three
sections that decide trunk exposure:

    PODS:              every resolved pod and version, subspecs included
    SPEC REPOS:        WHICH REPO each pod resolved from -- the decisive field
    EXTERNAL SOURCES:  pods pinned to a git/path/podspec source, bypassing trunk

The CocoaPods maintainer's freeze announcement is explicit that the freeze
"shouldn't affect people who use CocoaPods with their own specs repos, or have all of
their dependencies vendored". A scanner that ignores SPEC REPOS therefore reports false
alarms on exactly the projects that already did the right thing.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

try:
    import yaml
    _HAVE_YAML = True
except ImportError:  # pragma: no cover - environment dependent
    yaml = None  # type: ignore[assignment]
    _HAVE_YAML = False


# Every spelling of the central specs index seen in real lockfiles. Matching is done
# on a NORMALISED form (lowercase, no scheme, no trailing .git or slash) rather than by
# enumerating literals -- a real lockfile used "https://github.com/CocoaPods/Specs"
# without the .git suffix and was classified as a PRIVATE repo, i.e. reported as
# insulated from a freeze it is fully exposed to. That is the most damaging error this
# tool can make, so the comparison must not depend on punctuation.
TRUNK_REPO_KEYS = {
    "trunk",
    "master",
    "https://github.com/cocoapods/specs.git",
    "https://github.com/CocoaPods/Specs.git",
    "https://cdn.cocoapods.org/",
    "https://cdn.cocoapods.org",
}


def _normalise_repo(value: str) -> str:
    """Reduce a spec-repo identifier to a comparable form.

    'https://github.com/CocoaPods/Specs.git' -> 'github.com/cocoapods/specs'
    'git@github.com:CocoaPods/Specs.git'     -> 'github.com/cocoapods/specs'
    """
    v = value.strip().strip('"').strip("'").lower()
    v = re.sub(r"^[a-z0-9+.-]+://", "", v)          # scheme
    v = re.sub(r"^git@([^:]+):", r"\1/", v)          # scp-style git remote
    v = re.sub(r"\.git$", "", v)                     # trailing .git
    return v.rstrip("/")


TRUNK_REPO_NORMALISED = {_normalise_repo(k) for k in TRUNK_REPO_KEYS}

# "SDWebImage (5.18.10)" / "SDWebImage/Core (= 5.18.10)" / "Alamofire (~> 5.8)"
_ENTRY = re.compile(r"^\s*(?P<name>[^\s(]+)\s*(?:\((?P<ver>[^)]*)\))?\s*$")


class ParseError(ValueError):
    """Raised when input is not a recognisable Podfile.lock."""


@dataclass
class Pod:
    name: str                  # root pod name, subspec stripped
    raw_name: str              # as written, may include /Subspec
    version: str | None
    spec_repo: str | None = None
    external_source: dict | None = None
    is_subspec: bool = False

    @property
    def from_trunk(self) -> bool:
        if self.external_source:
            return False
        if self.spec_repo is None:
            # Not listed under any SPEC REPOS section. Older lockfiles (CocoaPods < 1.7)
            # omit the section entirely; those resolved from the master specs repo,
            # which is the same trunk index. Treated as trunk, and flagged as inferred.
            return True
        return _normalise_repo(self.spec_repo) in TRUNK_REPO_NORMALISED


@dataclass
class Lockfile:
    pods: list[Pod] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    spec_repos: dict[str, list[str]] = field(default_factory=dict)
    external_sources: dict[str, dict] = field(default_factory=dict)
    cocoapods_version: str | None = None
    spec_repos_section_present: bool = True

    def roots(self) -> list[Pod]:
        """One Pod per root package (subspecs folded in)."""
        seen: dict[str, Pod] = {}
        for p in self.pods:
            if p.name not in seen or (seen[p.name].is_subspec and not p.is_subspec):
                seen[p.name] = p
        return sorted(seen.values(), key=lambda p: p.name.lower())


def _root_name(raw: str) -> tuple[str, bool]:
    base = raw.split("/", 1)[0]
    return base, ("/" in raw)


def _entry_name_version(item) -> tuple[str, str | None]:
    """PODS entries are either a string or a single-key dict (pod with dependencies)."""
    if isinstance(item, dict):
        if not item:
            raise ParseError("empty mapping in PODS list")
        key = next(iter(item))
    else:
        key = item
    if not isinstance(key, str):
        raise ParseError(f"unexpected PODS entry type: {type(key).__name__}")
    m = _ENTRY.match(key)
    if not m:
        raise ParseError(f"unparseable pod entry: {key!r}")
    return m.group("name"), (m.group("ver") or None)


def parse(text: str) -> Lockfile:
    """Parse Podfile.lock text. Raises ParseError rather than silently returning empty.

    A scanner that swallows a parse failure reports 'nothing found', which is
    indistinguishable from a clean result. This raises instead.
    """
    if yaml is None:  # pragma: no cover
        raise ParseError("PyYAML is required to parse Podfile.lock")
    if not text.strip():
        raise ParseError("empty file")
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ParseError(f"not valid YAML: {e}") from e
    if not isinstance(doc, dict):
        raise ParseError("Podfile.lock must be a YAML mapping")
    if "PODS" not in doc and "DEPENDENCIES" not in doc:
        raise ParseError("no PODS or DEPENDENCIES section -- not a Podfile.lock")

    # A real Podfile.lock always carries a COCOAPODS version trailer. A file with PODS
    # but no trailer, no DEPENDENCIES and no SPEC REPOS was cut short -- and reporting
    # that as "legacy lockfile, sources unknown" states something false about a file
    # that was never fully read. A file reaching SPEC REPOS or DEPENDENCIES got far
    # enough to be analysed honestly, so those are accepted.
    has_trailer = any(k in doc for k in ("COCOAPODS", "SPEC CHECKSUMS", "PODFILE CHECKSUM"))
    got_far_enough = "DEPENDENCIES" in doc or "SPEC REPOS" in doc or "EXTERNAL SOURCES" in doc
    if "PODS" in doc and not has_trailer and not got_far_enough:
        raise ParseError(
            "file looks truncated: a PODS section with no DEPENDENCIES, SPEC REPOS or "
            "COCOAPODS trailer. A complete Podfile.lock ends with a COCOAPODS version "
            "line -- check the paste is complete")

    lock = Lockfile()
    lock.cocoapods_version = str(doc["COCOAPODS"]) if doc.get("COCOAPODS") else None

    ext = doc.get("EXTERNAL SOURCES") or {}
    if isinstance(ext, dict):
        lock.external_sources = {str(k): (v if isinstance(v, dict) else {"raw": v})
                                 for k, v in ext.items()}

    repos = doc.get("SPEC REPOS")
    lock.spec_repos_section_present = repos is not None
    # A pod name can appear under more than one spec repo in a malformed or hand-edited
    # lockfile. Keep ALL sources rather than letting the last one win: under-reporting
    # exposure is the dangerous direction for this tool, so ambiguity must resolve
    # toward "exposed", not toward "safe".
    pod_to_repos: dict[str, list[str]] = {}
    if isinstance(repos, dict):
        for repo, names in repos.items():
            names = names or []
            if not isinstance(names, list):
                continue
            lock.spec_repos[str(repo)] = [str(n) for n in names]
            for n in names:
                pod_to_repos.setdefault(str(n), []).append(str(repo))

    def _pick_repo(root: str) -> str | None:
        """Resolve a pod's spec repo, preferring trunk when sources conflict."""
        sources = pod_to_repos.get(root)
        if not sources:
            return None
        trunk_keys = {k.lower() for k in TRUNK_REPO_KEYS}
        for s in sources:
            if s.strip().lower() in trunk_keys:
                return s          # conservative: any trunk source ⇒ exposed
        return sources[0]

    for item in (doc.get("PODS") or []):
        raw, ver = _entry_name_version(item)
        root, is_sub = _root_name(raw)
        lock.pods.append(Pod(
            name=root,
            raw_name=raw,
            version=ver,
            spec_repo=_pick_repo(root),
            external_source=lock.external_sources.get(root),
            is_subspec=is_sub,
        ))

    for dep in (doc.get("DEPENDENCIES") or []):
        if isinstance(dep, str):
            lock.dependencies.append(dep)

    return lock
