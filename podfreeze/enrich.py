"""Pro enrichment — verified public data only.

DATA SOURCES, AND WHAT EACH IS PROVEN TO GIVE
---------------------------------------------
1. https://trunk.cocoapods.org/api/v1/pods/<name>
   Returns every published version with its publication date. VERIFIED working.
   Gives: latest published version + date -> how stale the pod already is.

2. https://raw.githubusercontent.com/<owner>/<repo>/<branch>/Package.swift
   Presence of Package.swift proves a SwiftPM migration target exists. VERIFIED.

WHAT THIS DELIBERATELY DOES NOT CLAIM
-------------------------------------
There is NO vulnerability database for CocoaPods. Verified directly:
  - OSV.dev  -> {"code":3,"message":"invalid ecosystem"} for ecosystem "CocoaPods"
  - GitHub   -> 422, "`cocoapods` is not a possible value"
GitHub's `swift` ecosystem exists but indexes SwiftPM packages (apple/swift-nio etc.),
not CocoaPods pod names, so joining pod names against it would return near-universal
"no advisories" -- a broken join indistinguishable from a clean result.

This tool therefore reports NO CVE data and says so plainly. Any product claiming
per-pod CVE scanning for CocoaPods is either using a private dataset or is wrong.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict

TRUNK_API = "https://trunk.cocoapods.org/api/v1/pods/{name}"
RAW_PKG = "https://raw.githubusercontent.com/{repo}/{branch}/Package.swift"

# Pods published from a shared monorepo, where the owner/name guess gives a FALSE
# negative. Every slug here was verified to serve a real Package.swift (HTTP 200) --
# none are from memory. Firebase alone publishes ~40 pods from one repository, and the
# Firebase pods are exactly the ones facing the earlier October 2026 vendor cutoff, so
# telling a buyer "no SwiftPM target found" for them would be both wrong and expensive.
KNOWN_MONOREPOS = {
    "FirebaseAnalytics": "firebase/firebase-ios-sdk",
    "FirebaseAuth": "firebase/firebase-ios-sdk",
    "FirebaseCore": "firebase/firebase-ios-sdk",
    "FirebaseCrashlytics": "firebase/firebase-ios-sdk",
    "FirebaseDatabase": "firebase/firebase-ios-sdk",
    "FirebaseDynamicLinks": "firebase/firebase-ios-sdk",
    "FirebaseFirestore": "firebase/firebase-ios-sdk",
    "FirebaseInAppMessaging": "firebase/firebase-ios-sdk",
    "FirebaseMessaging": "firebase/firebase-ios-sdk",
    "FirebasePerformance": "firebase/firebase-ios-sdk",
    "FirebaseRemoteConfig": "firebase/firebase-ios-sdk",
    "FirebaseStorage": "firebase/firebase-ios-sdk",
    "Firebase": "firebase/firebase-ios-sdk",
    "GoogleUtilities": "google/GoogleUtilities",
    "GoogleSignIn": "google/GoogleSignIn-iOS",
    "GTMSessionFetcher": "google/gtm-session-fetcher",
    "AppAuth": "openid/AppAuth-iOS",
    "Sentry": "getsentry/sentry-cocoa",
    "Realm": "realm/realm-swift",
    "RealmSwift": "realm/realm-swift",
}
from . import __version__ as _v  # noqa: E402
UA = f"podfreeze/{_v} (+https://github.com/ntoledo319/podfreeze)"
TIMEOUT = 12
# Star floor for accepting a GitHub search hit as the canonical source of a pod. Chosen
# from measurement, not taste: the top "IQKeyboardManagerSwift" hit is a 74-star copy
# while the real project has ~16k, and every correctly-resolved pod in the sample
# (KSCrash 4.5k, SnapKit 20k, Alamofire 42k, RxSwift 24k, SwiftLint 19k) clears this by
# an order of magnitude. Set high deliberately: a wrong migration target is worse than
# an honest "not found".
#
# KNOWN COST, measured: this rejects at least one genuinely canonical project --
# tladesignz/IPtProxy (77 stars, actively maintained, exact name match) is the real
# source and is reported as "not found". That is the deliberate trade.
#
# A "nothing bigger shares this name" rule was tested as a way to lower the floor safely
# and REJECTED: the real IQKeyboardManagerSwift lives under a different repository name
# (hackiftekhar/IQKeyboardManager), so it never appears in a search for the pod name --
# the 74-star copy looks undisputed and would be accepted. No search-based signal
# distinguishes "small but canonical" from "small impostor whose original is named
# differently", so the floor stays, and the report says "not found" rather than guessing.
CANONICAL_STARS = 500
_NET_STATE: bool | None = None


@dataclass
class Enrichment:
    pod: str
    latest_version: str | None = None
    latest_published: str | None = None      # YYYY-MM-DD
    total_versions: int | None = None
    swiftpm_repo: str | None = None
    swiftpm_available: bool | None = None    # None = could not determine
    error: str | None = None

    def as_dict(self):
        return asdict(self)


def _get(url: str) -> bytes | None:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.read()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return None


def _head_ok(url: str) -> bool:
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="HEAD")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return 200 <= r.status < 300
    except Exception:
        return False


def _network_up() -> bool:
    """One cheap probe so a network outage is reported as an outage, not as a finding.

    Cached per process: a scan of 40 pods must not make 40 extra probes.
    """
    global _NET_STATE
    if _NET_STATE is None:
        _NET_STATE = _get("https://trunk.cocoapods.org/api/v1/pods/Alamofire") is not None
    return _NET_STATE


def fetch_trunk(name: str) -> tuple[str | None, str | None, int | None, str | None]:
    """Return (latest_version, published_date, total_versions, error).

    Distinguishes network failure from "this pod is not on trunk" — conflating them
    would tell a user their pod is absent when the lookup simply could not run.
    """
    raw = _get(TRUNK_API.format(name=name))
    if raw is None:
        if not _network_up():
            return None, None, None, "NETWORK UNAVAILABLE — lookup could not run"
        return None, None, None, "not found on trunk (or the API rejected the name)"
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        return None, None, None, "trunk API returned non-JSON"
    versions = doc.get("versions") or []
    if not versions:
        return None, None, None, "no published versions"
    last = versions[-1]
    date = (last.get("created_at") or "")[:10] or None
    return last.get("name"), date, len(versions), None


def find_swiftpm(name: str, cocoapods_doc: dict | None = None) -> tuple[str | None, bool | None]:
    """Probe the conventional GitHub location for a Package.swift.

    Returns (repo_slug, available). available is None when it cannot be determined --
    never guessed. Absence of Package.swift at the conventional path does NOT prove the
    library has no SwiftPM support, so a negative is reported as 'not found at the
    conventional path', not as 'no SwiftPM support'.

    The CocoaPods trunk API does not expose a pod's source repository (it returns only
    versions and owners), so the owner/name guess is the only general probe available.
    It is wrong for vendors who ship many pods from one monorepo -- Firebase publishes
    ~40 pods from firebase/firebase-ios-sdk, so guessing FirebaseAuth/FirebaseAuth
    misses a Package.swift that plainly exists. Those are resolved from a small explicit
    map of verified monorepos rather than reported as a false negative.
    """
    slug = KNOWN_MONOREPOS.get(name.split("/")[0])
    if slug:
        for branch in ("main", "master"):
            if _head_ok(RAW_PKG.format(repo=slug, branch=branch)):
                return slug, True

    repo = f"{name}/{name}"
    for branch in ("master", "main"):
        if _head_ok(RAW_PKG.format(repo=repo, branch=branch)):
            return repo, True

    # Last resort: GitHub repository search. Held to a deliberately strict rule,
    # because the failure mode here is worse than "not found" -- a naive top-hit lookup
    # for IQKeyboardManagerSwift returns a 74-star copy rather than the real 16k-star
    # project, and pointing a buyer at a stranger's fork as their migration target is
    # a more damaging answer than admitting the probe could not resolve it.
    #
    # Accepted only when the repository name matches EXACTLY, it is not a fork, it
    # carries enough stars to be plainly canonical, and it really serves a Package.swift.
    slug, ok = _search_swiftpm(name.split("/")[0])
    if ok:
        return slug, True

    return repo, None


SEARCH_BLOCKED = {"count": 0}


def _search_swiftpm(pod: str) -> tuple[str | None, bool]:
    """Find a canonical repo for a pod via GitHub search, or give up honestly.

    Records rate-limit refusals in SEARCH_BLOCKED so the report can tell a reader that
    the probe could not run, rather than presenting 58 unresolved rows that look
    identical to a genuine negative. Unauthenticated GitHub search allows only 10
    requests per minute; a real audit needs far more.
    """
    try:
        import json as _json
        url = ("https://api.github.com/search/repositories?q="
               + urllib.parse.quote(f"{pod} in:name") + "&sort=stars&per_page=5")
        req = urllib.request.Request(url, headers={"User-Agent": UA,
                                                   "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            items = _json.loads(r.read()).get("items", [])
    except urllib.error.HTTPError as e:
        # 403/429 from search is a rate limit, not a verdict about the pod.
        if e.code in (403, 429):
            SEARCH_BLOCKED["count"] += 1
        return None, False
    except Exception:  # noqa: BLE001 - search is a bonus, never a requirement
        return None, False

    for it in items:
        if it.get("name", "").lower() != pod.lower():
            continue
        if it.get("fork"):
            continue
        if it.get("stargazers_count", 0) < CANONICAL_STARS:
            continue
        # Pod names collide ACROSS ecosystems. "Eureka" is both a Swift forms library
        # (xmartlabs, ~11k stars) and Netflix's Java service registry (~12.7k). Stars
        # alone would pick the Java one. Requiring a Package.swift already excludes it
        # in practice, but relying on that is luck rather than design: a Java project
        # that happens to vendor a Package.swift would slip through.
        lang = (it.get("language") or "").lower()
        if lang and lang not in ("swift", "objective-c", "objective-c++", "c", "c++"):
            continue
        full = it.get("full_name", "")
        for branch in ("main", "master"):
            if _head_ok(RAW_PKG.format(repo=full, branch=branch)):
                return full, True
    return None, False


def enrich_one(name: str) -> Enrichment:
    ver, date, count, err = fetch_trunk(name)
    e = Enrichment(pod=name, latest_version=ver, latest_published=date,
                   total_versions=count, error=err)
    repo, avail = find_swiftpm(name)
    e.swiftpm_repo = repo
    e.swiftpm_available = avail
    return e


def enrich(names: list[str], workers: int = 8) -> list[Enrichment]:
    if not names:
        return []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(enrich_one, names))
