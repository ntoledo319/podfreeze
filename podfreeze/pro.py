"""Pro report rendering + license gating.

The free tool is complete and useful on its own: it tells you exactly which pods are
exposed. Pro answers the next question -- what do I do about each one, and in what
order -- using live data from the CocoaPods trunk API and SwiftPM availability probes.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import os

from .analyse import FREEZE_DATE, Report
from .enrich import Enrichment, enrich

# Licence keys are signed with this public tag + a secret held only by the seller.
# Verification is offline: no phone-home, no telemetry, works air-gapped.
_LICENSE_PREFIX = "PDFZ1"


def verify_license(key: str | None, secret: str | None = None) -> bool:
    """Offline licence check. Format: PDFZ1-<payload>-<sig>.

    Deliberately simple and offline. This is a paywall for honest buyers, not DRM;
    it does not phone home and stores nothing.

    Tolerant of how a real buyer actually pastes a key: surrounding whitespace, and
    case. A paying customer locked out by a lowercased key is a refund and a bad
    review, and the key carries no secrecy that case-sensitivity would protect.
    """
    key = (key or os.environ.get("PODFREEZE_LICENSE") or "").strip().upper()
    secret = secret or os.environ.get("PODFREEZE_SECRET") or ""
    if not key or not key.startswith(_LICENSE_PREFIX):
        return False
    parts = key.split("-")
    if len(parts) != 3:
        return False
    _, payload, sig = parts
    if not secret:
        # No secret configured locally: accept a well-formed key. The seller signs keys;
        # buyers never need the secret. Structure check only.
        return len(payload) >= 8 and len(sig) >= 8
    expect = hmac.new(secret.encode(), payload.encode(),
                      hashlib.sha256).hexdigest()[:16].upper()
    return hmac.compare_digest(expect, sig)


def _age_days(date_str: str | None) -> int | None:
    if not date_str:
        return None
    try:
        d = _dt.date.fromisoformat(date_str)
    except ValueError:
        return None
    return (_dt.date.today() - d).days


def _priority(e: Enrichment) -> tuple[int, str]:
    """Rank by what you actually LOSE at the freeze. Evidence-based, no invented severity.

    Ranked actively-published pods last until v0.5.2, which was backwards. A pod that
    has not published in three years loses nothing on 2 December -- nobody was shipping
    fixes for it, and the freeze only formalises a state that already exists. A pod
    shipping releases this year loses a live channel its maintainers are actively using,
    including for security patches. Real example from measured data: GoogleUtilities
    published three times in 2026 and appears in 18 of 83 surveyed projects.
    """
    age = _age_days(e.latest_published)
    if e.error:
        return (3, "could not determine")
    if age is not None and age <= 365:
        return (0, "actively published — loses a live release channel at the freeze")
    if age is not None and age <= 365 * 3:
        return (1, f"last published {age // 365}y ago")
    if age is not None:
        return (2, f"last published {age // 365}y ago — effectively frozen already")
    return (3, "could not determine")


def render_pro(rep: Report, licensed: bool) -> str:
    L: list[str] = []
    a = L.append
    exposed = rep.exposed
    if not licensed:
        a("")
        a("  PRO — migration plan for the pods above")
        a("")
        a("  Pro adds, for each exposed pod:")
        a("    - last published version and date (from the CocoaPods trunk API)")
        a("    - how long it has been since that pod moved at all")
        a("    - whether a SwiftPM target exists to migrate to")
        a("    - a ranked order of what to deal with first")
        a("")
        a("  https://github.com/ntoledo319/podfreeze#pro")
        a("")
        return "\n".join(L)

    names = [f.pod.name for f in exposed]
    a("")
    a("  PRO — migration plan")
    a("")
    if not names:
        a("  No trunk-exposed pods. Nothing to plan.")
        a("")
        return "\n".join(L)

    a(f"  Querying the CocoaPods trunk API for {len(names)} pod(s)...")
    a("")
    data = {e.pod: e for e in enrich(names)}
    ranked = sorted(exposed, key=lambda f: _priority(data[f.pod.name]))

    for f in ranked:
        e = data[f.pod.name]
        rank, why = _priority(e)
        a(f"    {f.pod.name}")
        a(f"      in your lockfile : {f.pod.version or 'unknown'}")
        if e.error:
            a(f"      trunk lookup     : {e.error}")
        else:
            a(f"      latest on trunk  : {e.latest_version} (published {e.latest_published})")
            a(f"      total versions   : {e.total_versions}")
            a(f"      assessment       : {why}")
        if e.swiftpm_available:
            a(f"      SwiftPM          : Package.swift found at {e.swiftpm_repo}")
        elif e.error and "NETWORK" in e.error:
            a(f"      SwiftPM          : not checked (network unavailable)")
        else:
            a(f"      SwiftPM          : not found at the conventional path "
              f"({e.swiftpm_repo}); check the project's own docs")
        a("")

    a("  ORDER OF WORK")
    a("")
    a("  Deal with the pods listed first: they are still shipping releases, so the")
    a(f"  {FREEZE_DATE} freeze takes away a live update channel — including the route")
    a("  a security fix would travel. A pod that has not published in years is already")
    a("  static in practice; the freeze only makes that permanent, and migrating it is")
    a("  housekeeping rather than risk.")
    a("")
    a("  NOTE ON VULNERABILITY DATA")
    a("")
    a("  This report contains no CVE data, deliberately. There is no vulnerability")
    a("  database covering the CocoaPods ecosystem: OSV.dev rejects it as an invalid")
    a("  ecosystem, and GitHub's advisory API does not accept `cocoapods`. Matching")
    a("  pod names against GitHub's `swift` ecosystem returns near-universal 'no")
    a("  advisories' — a broken lookup that looks identical to a clean result.")
    a("  Any tool claiming per-pod CVE scanning for CocoaPods is worth questioning.")
    a("")
    return "\n".join(L)
