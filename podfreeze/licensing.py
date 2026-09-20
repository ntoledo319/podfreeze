"""Offline licence keys that a buyer's machine can actually verify.

The problem this replaces
-------------------------
Earlier builds used a licence key of the form ``PDFZ1-<payload>-<sig>`` where ``<sig>`` was an HMAC over
``<payload>`` keyed with ``PODFREEZE_SECRET``. HMAC is symmetric: verifying the signature
needs the same secret that produced it. That secret is the seller's and cannot be shipped,
so on every buyer's machine it was unset -- and the unset branch fell back to
``len(payload) >= 8 and len(sig) >= 8``. Any string of the right shape passed. Three
fabricated keys were confirmed to verify. Nothing in the key said which tier it was, so a
US$29 key and a US$499 key were the same object.

The fix
-------
An Ed25519 signature is asymmetric: the seller signs with a private key, and anyone can
verify with the public half. The public half ships in this package (``_pubkey.py``), the
private half never leaves the seller. Verification is offline, needs no secret, makes no
network call, and works air-gapped -- the same promise as before, now actually kept.

The tier is inside the signed payload, so it cannot be edited without invalidating the
signature, and ``verify_license`` returns the tier rather than a bare bool.

Key format
----------
``PDFZ2-<payload>-<signature>``

* ``payload`` is unpadded RFC 4648 base32 of ``podfreeze|v2|<tier>|<expiry>|<nonce>``
* ``signature`` is unpadded base32 of the 64-byte Ed25519 signature over those exact
  payload bytes
* base32 is used rather than base64 because its alphabet is case-insensitive, so a key
  that survives being lower-cased in an email client still verifies -- the paste
  tolerance the old check had, kept.

The product name is inside the signed bytes, so a key minted for something else cannot be
replayed here.

What this is not
----------------
podfreeze is MIT licensed and its source is public. Anyone can delete this module and the
two call sites that use it. A signature check makes a *forged* key impossible; it cannot
make a *patched* copy impossible, and no client-side check in an open-source package can.
This is a correct lock on an honest door, and it is described that way in the README
rather than sold as protection it cannot give.
"""
from __future__ import annotations

import base64
import binascii
import datetime as _dt
import os
import re
from dataclasses import dataclass

from . import _ed25519
from ._pubkey import PUBLIC_KEY_HEX

__all__ = [
    "Licence", "TIERS", "KEY_PREFIX", "PAYLOAD_PREFIX",
    "build_payload", "encode_key", "verify_license", "check_license",
]

KEY_PREFIX = "PDFZ2"
PAYLOAD_PREFIX = "podfreeze|v2"

#: Tier name -> rank. A higher rank satisfies every requirement a lower rank satisfies.
TIERS = {"single": 1, "team": 2, "org": 3}

#: What each tier is sold as, for messages the buyer reads.
TIER_LABELS = {
    "single": "single project",
    "team": "team",
    "org": "organisation audit",
}

_NONCE_RE = re.compile(r"\A[0-9a-f]{8,32}\Z")
_DATE_RE = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")

# Reason codes. The CLI turns these into sentences; tests assert on them.
OK = "ok"
NO_KEY = "no-key"
UNCONFIGURED = "unconfigured"
MALFORMED = "malformed"
BAD_SIGNATURE = "bad-signature"
EXPIRED = "expired"
TIER_TOO_LOW = "tier-too-low"


@dataclass(frozen=True)
class Licence:
    """A licence key whose signature has been verified against the shipped public key."""

    tier: str
    expires: str          # an ISO date, or "never"
    nonce: str

    @property
    def rank(self) -> int:
        return TIERS[self.tier]

    @property
    def label(self) -> str:
        return TIER_LABELS.get(self.tier, self.tier)

    def permits(self, needed: str) -> bool:
        return self.rank >= TIERS[needed]


def _b32encode(raw: bytes) -> str:
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _b32decode(text: str) -> bytes | None:
    pad = (-len(text)) % 8
    try:
        return base64.b32decode(text + "=" * pad, casefold=True)
    except (binascii.Error, ValueError):
        return None


def build_payload(tier: str, expires: str, nonce: str) -> bytes:
    """The exact bytes that get signed. Seller and buyer must agree on them byte for byte."""
    if tier not in TIERS:
        raise ValueError(f"unknown tier {tier!r}; expected one of {sorted(TIERS)}")
    if expires != "never" and not _DATE_RE.match(expires):
        raise ValueError("expires must be 'never' or an ISO date, YYYY-MM-DD")
    if not _NONCE_RE.match(nonce):
        raise ValueError("nonce must be 8-32 lowercase hex characters")
    return f"{PAYLOAD_PREFIX}|{tier}|{expires}|{nonce}".encode("utf-8")


def encode_key(payload: bytes, signature: bytes) -> str:
    """Assemble the printable key. Used by the seller's minting tool."""
    return f"{KEY_PREFIX}-{_b32encode(payload)}-{_b32encode(signature)}"


def _parse_payload(raw: bytes) -> Licence | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    parts = text.split("|")
    if len(parts) != 5:
        return None
    product, version, tier, expires, nonce = parts
    if f"{product}|{version}" != PAYLOAD_PREFIX:
        return None
    if tier not in TIERS:
        return None
    if expires != "never" and not _DATE_RE.match(expires):
        return None
    if not _NONCE_RE.match(nonce):
        return None
    return Licence(tier=tier, expires=expires, nonce=nonce)


def _public_key_bytes(public_key: bytes | str | None) -> bytes | None:
    """Resolve the verifying key. Never read from the environment.

    An env-var override here would reintroduce the original bug in a new shape: anyone
    could point podfreeze at their own public key and mint their own licences.
    """
    if public_key is None:
        public_key = PUBLIC_KEY_HEX
    if isinstance(public_key, str):
        text = public_key.strip()
        if not text:
            return None
        try:
            public_key = binascii.unhexlify(text)
        except (binascii.Error, ValueError):
            return None
    if len(public_key) != _ed25519.KEY_BYTES:
        return None
    return bytes(public_key)


def check_license(
    key: str | None = None,
    *,
    need: str = "single",
    public_key: bytes | str | None = None,
    today: _dt.date | None = None,
) -> tuple[Licence | None, str]:
    """Verify a key and check it against the tier a command requires.

    Returns ``(licence, reason)``. ``reason`` is :data:`OK` only when the signature
    verified, the key has not expired, and the tier is sufficient. On every other path the
    licence is ``None`` and the reason says which check refused it, so the CLI can tell a
    buyer who mistyped a key from a buyer whose key is for a cheaper tier.
    """
    if need not in TIERS:
        raise ValueError(f"unknown tier {need!r}")

    raw_key = key if key is not None else os.environ.get("PODFREEZE_LICENSE")
    text = (raw_key or "").strip()
    if not text:
        return None, NO_KEY

    verifying_key = _public_key_bytes(public_key)
    if verifying_key is None:
        # No seller key in this build. Refuse everything rather than wave everything
        # through: this is the exact branch the previous implementation got backwards.
        return None, UNCONFIGURED

    text = text.upper()
    parts = text.split("-")
    if len(parts) != 3 or parts[0] != KEY_PREFIX:
        return None, MALFORMED
    payload_raw = _b32decode(parts[1])
    signature = _b32decode(parts[2])
    if payload_raw is None or signature is None:
        return None, MALFORMED
    if len(signature) != _ed25519.SIGNATURE_BYTES:
        return None, MALFORMED
    licence = _parse_payload(payload_raw)
    if licence is None:
        return None, MALFORMED

    if not _ed25519.verify(payload_raw, signature, verifying_key):
        # Well-formed and completely unsigned keys land here. They used to pass.
        return None, BAD_SIGNATURE

    if licence.expires != "never":
        now = today or _dt.date.today()
        try:
            until = _dt.date.fromisoformat(licence.expires)
        except ValueError:
            return None, MALFORMED
        if now > until:
            return None, EXPIRED

    if not licence.permits(need):
        return licence, TIER_TOO_LOW

    return licence, OK


def verify_license(
    key: str | None = None,
    *,
    public_key: bytes | str | None = None,
    today: _dt.date | None = None,
) -> Licence | None:
    """Return the verified :class:`Licence`, or ``None`` if the key is not valid.

    The return value carries the tier. It used to be a bare ``bool``, which is why
    ``--pro`` at US$29 and ``--audit`` at US$499 consulted the same answer.
    """
    licence, reason = check_license(key, need="single", public_key=public_key, today=today)
    return licence if reason == OK else None
