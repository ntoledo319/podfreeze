"""Pro report rendering + license gating.

The free tool is complete and useful on its own: it tells you exactly which pods are
exposed. Pro answers the next question -- what do I do about each one, and in what
order -- using live data from the CocoaPods trunk API and SwiftPM availability probes.

The licence check itself lives in :mod:`podfreeze.licensing`. It is an Ed25519 signature
verified against a public key shipped in this package: offline, no phone-home, and -- the
part that was broken before this change -- no seller secret on the buyer's machine.
"""
from __future__ import annotations

import datetime as _dt

from .analyse import FREEZE_DATE, Report
from .enrich import Enrichment, enrich
from .licensing import (BAD_SIGNATURE, EXPIRED, MALFORMED, NO_KEY, OK,  # noqa: F401
                        TIER_TOO_LOW, UNCONFIGURED, Licence, check_license,
                        verify_license)

# Retained as a name because the CLI and tests import it from here; the check is in
# licensing.py so that the signature logic and the report rendering are not one file.
_LICENSE_PREFIX = "PDFZ2"

SUPPORT_URL = "https://github.com/ntoledo319/podfreeze/issues"
PRO_URL = "https://github.com/ntoledo319/podfreeze#pro"
# A buyer chasing a licence key should not have to describe their purchase in a public
# issue tracker to get it. This inbox is monitored; the issue tracker stays as the public
# alternative for anyone who prefers one.
SUPPORT_EMAIL = "hello@toledotechnologies.com"


def licence_problem_lines(reason: str, licence: Licence | None = None,
                          needed: str = "single") -> list[str]:
    """The buyer-facing explanation for a refused key, one line per list entry.

    Each refusal reason gets its own words. A buyer who mistyped a key, a buyer holding a
    cheaper tier, and a buyer whose key expired are three different conversations, and
    showing all three the same upsell is how a paying customer concludes they were never
    sent a key at all.
    """
    from .licensing import TIER_LABELS
    if reason == UNCONFIGURED:
        return [
            "  LICENSING IS NOT CONFIGURED IN THIS BUILD",
            "",
            "  This copy of podfreeze ships no licence public key, so it cannot verify",
            "  any key -- including a valid one. The free scan above is unaffected.",
            "",
            f"  Please report this build: {SUPPORT_EMAIL}",
            f"  or {SUPPORT_URL}",
        ]
    if reason == EXPIRED and licence is not None:
        return [
            "  LICENCE KEY EXPIRED",
            "",
            f"  This key was valid until {licence.expires}.",
            "",
            f"  If that is wrong, say so and it will be fixed or refunded:",
            f"  {SUPPORT_EMAIL}, or {SUPPORT_URL}",
        ]
    if reason == TIER_TOO_LOW and licence is not None:
        return [
            "  THIS COMMAND NEEDS A HIGHER TIER",
            "",
            f"  Your key is a {licence.label} licence. This command needs the "
            f"{TIER_LABELS.get(needed, needed)} licence.",
            "",
            f"  Tiers and prices: {PRO_URL}",
        ]
    return [
        "  LICENCE KEY NOT RECOGNISED",
        "",
        "  A key was supplied but its signature did not verify. Keys look like",
        "    PDFZ2-<letters and digits>-<letters and digits>",
        "  and are emailed to you after payment, to the address on your Stripe",
        "  receipt. Check for a missing or dropped character -- the whole key is signed,",
        "  so one wrong character is enough. Case and surrounding whitespace do not",
        "  matter; the check normalises both.",
        "",
        "  If it still fails, or no key ever reached you, it will be re-issued or",
        "  refunded:",
        f"  {SUPPORT_EMAIL}, or {SUPPORT_URL}",
    ]


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


def render_pro(rep: Report, licensed: bool, key_supplied: bool = False,
               reason: str | None = None, licence: Licence | None = None) -> str:
    """Render the Pro section.

    ``reason`` and ``licence`` come from :func:`podfreeze.licensing.check_license` and let
    this say *why* a key was refused. They are optional so the older two-argument call
    still works.
    """
    L: list[str] = []
    a = L.append
    exposed = rep.exposed
    if not licensed:
        a("")
        if key_supplied or reason in (UNCONFIGURED, EXPIRED, TIER_TOO_LOW):
            # A buyer who typos their key was shown the same upsell as someone who
            # never bought -- so the natural conclusion is "I was never sent a key",
            # not "I mistyped it". Say which it is.
            for line in licence_problem_lines(reason or BAD_SIGNATURE, licence):
                a(line)
            a("")
            return "\n".join(L)
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
