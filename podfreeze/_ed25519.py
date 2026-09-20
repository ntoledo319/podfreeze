"""Ed25519 signature verification, standard library only.

Why this file exists
--------------------
podfreeze ships as an ordinary pip package with no dependencies beyond PyYAML. A licence
check that needs a real signature therefore needs a real signature algorithm, and the
Python standard library has no asymmetric cryptography: ``hashlib`` and ``hmac`` give
hashing and symmetric authentication only. An HMAC check needs the *same* secret on both
sides, which is precisely the design that failed here -- the seller's secret cannot be put
on a buyer's machine, so the check degraded to a length test.

Ed25519 (RFC 8032) needs nothing but SHA-512 and integer arithmetic, both of which the
standard library has. This module is a direct transcription of the RFC 8032 procedures.
It is verified in the test suite against the RFC 8032 section 7.1 test vectors, so it is
this implementation that is on trial, not the reader's trust in it.

Honest limits, stated here rather than in a sales page:

* This is a readable reference implementation, not a constant-time one. Signature
  *verification* handles only public data -- a public key, a message and a signature that
  anyone may hold -- so timing leakage on that path reveals nothing secret. Signing and
  key generation, which do touch a private key, are used only by the seller's own minting
  tool (``tools/mint_license.py``); they are not on any buyer code path and must not be
  used to protect anything more valuable than a licence key.
* It implements Ed25519 (PureEdDSA over edwards25519), not Ed25519ph or Ed25519ctx.
* Verification uses the RFC 8032 equation ``[S]B == R + [k]A`` without cofactor
  multiplication. This is the non-cofactored check most libraries perform; it is
  deliberate and recorded here so nobody has to guess which variant is in use.
"""
from __future__ import annotations

import hashlib

__all__ = ["verify", "sign", "public_key_from_seed", "SIGNATURE_BYTES", "KEY_BYTES"]

SIGNATURE_BYTES = 64
KEY_BYTES = 32

# Curve parameters, RFC 8032 section 5.1.
_P = 2 ** 255 - 19                                                    # field prime
_L = 2 ** 252 + 27742317777372353535851937790883648493                # group order


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


_D = -121665 * _inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)

# Extended homogeneous coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z, x*y = T/Z.
_IDENTITY = (0, 1, 1, 0)


def _sha512_int(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little")


def _recover_x(y: int, sign_bit: int) -> int | None:
    """Recover x from y and the encoded sign bit, or None if y is not on the curve."""
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign_bit else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if x & 1 != sign_bit:
        x = _P - x
    return x


def _add(p: tuple, q: tuple) -> tuple:
    """Unified extended-coordinate addition; correct for doubling too (RFC 8032 A.1)."""
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * t1 * t2 * _D % _P
    d = 2 * z1 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _scalar_mult(p: tuple, e: int) -> tuple:
    """Double-and-add. Iterative, so a 256-bit scalar cannot exhaust the stack."""
    result = _IDENTITY
    addend = p
    while e > 0:
        if e & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        e >>= 1
    return result


def _equal(p: tuple, q: tuple) -> bool:
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


_BASE_Y = 4 * _inv(5) % _P
_BASE_X = _recover_x(_BASE_Y, 0)
if _BASE_X is None:  # pragma: no cover - only reachable if the constants are edited
    # Not an assert: `python -O` strips asserts, and a silently wrong base point would
    # make every signature check meaningless rather than loudly broken.
    raise RuntimeError("edwards25519 base point failed to decode")
_BASE = (_BASE_X, _BASE_Y, 1, _BASE_X * _BASE_Y % _P)


def _compress(p: tuple) -> bytes:
    x, y, z, _ = p
    zi = _inv(z)
    x = x * zi % _P
    y = y * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decompress(data: bytes) -> tuple | None:
    if len(data) != 32:
        return None
    raw = int.from_bytes(data, "little")
    sign_bit = raw >> 255
    y = raw & ((1 << 255) - 1)
    x = _recover_x(y, sign_bit)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _expand_seed(seed: bytes) -> tuple:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8      # clear the low 3 bits
    a |= 1 << 254            # set bit 254, clear bit 255
    return a, h[32:]


def public_key_from_seed(seed: bytes) -> bytes:
    """Derive the 32-byte public key from a 32-byte private seed. Seller side only."""
    if len(seed) != KEY_BYTES:
        raise ValueError("an Ed25519 private seed is exactly 32 bytes")
    a, _ = _expand_seed(seed)
    return _compress(_scalar_mult(_BASE, a))


def sign(message: bytes, seed: bytes) -> bytes:
    """Produce a 64-byte Ed25519 signature. Seller side only; not constant time."""
    if len(seed) != KEY_BYTES:
        raise ValueError("an Ed25519 private seed is exactly 32 bytes")
    a, prefix = _expand_seed(seed)
    pub = _compress(_scalar_mult(_BASE, a))
    r = _sha512_int(prefix + message) % _L
    big_r = _compress(_scalar_mult(_BASE, r))
    k = _sha512_int(big_r + pub + message) % _L
    s = (r + k * a) % _L
    return big_r + s.to_bytes(32, "little")


def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Check an Ed25519 signature. Returns False for any malformed input.

    This is the only function a buyer's machine runs, and it needs no secret of any kind.
    """
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != SIGNATURE_BYTES:
        return False
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != KEY_BYTES:
        return False
    signature = bytes(signature)
    public_key = bytes(public_key)
    big_r = _decompress(signature[:32])
    point_a = _decompress(public_key)
    if big_r is None or point_a is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        # A non-canonical S is the classic malleability foothold: reject rather than
        # reduce, so one licence key cannot be rewritten into a second valid key.
        return False
    k = _sha512_int(signature[:32] + public_key + message) % _L
    return _equal(_scalar_mult(_BASE, s), _add(big_r, _scalar_mult(point_a, k)))
