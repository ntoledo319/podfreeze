"""A throwaway seller keypair, so tests can mint the keys a real buyer would receive.

The shipped package holds only a public key. To test that a *genuine* key works -- and
that a forged one does not -- the tests need the private half, so they generate their own
and tell podfreeze to verify against the matching public half. Nothing here is a secret:
the keypair lives for the length of one test session.
"""
from __future__ import annotations

import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from podfreeze import _ed25519                                      # noqa: E402
from podfreeze.licensing import build_payload, encode_key           # noqa: E402

SEED = secrets.token_bytes(_ed25519.KEY_BYTES)
PUBLIC_HEX = _ed25519.public_key_from_seed(SEED).hex()

# A second, unrelated keypair: signatures from this one must never verify.
OTHER_SEED = secrets.token_bytes(_ed25519.KEY_BYTES)
OTHER_PUBLIC_HEX = _ed25519.public_key_from_seed(OTHER_SEED).hex()


def mint(tier: str = "single", expires: str = "never", nonce: str = "0123abcd",
         seed: bytes = SEED) -> str:
    """Mint a genuinely signed licence key, the way the seller's tool would."""
    payload = build_payload(tier, expires, nonce)
    return encode_key(payload, _ed25519.sign(payload, seed))


def unsigned(tier: str = "org", expires: str = "never", nonce: str = "0123abcd") -> str:
    """A key with a perfectly well-formed payload and a signature that signs nothing.

    This is the shape the old check could not tell from a real key.
    """
    payload = build_payload(tier, expires, nonce)
    return encode_key(payload, bytes(_ed25519.SIGNATURE_BYTES))
