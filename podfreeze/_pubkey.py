"""The seller's Ed25519 licence public key, as shipped.

This file is data, not logic. ``tools/mint_license.py keygen`` writes it; nothing else
should. The private half never appears in this repository and never reaches a buyer.

An empty value means this build has no seller key configured, and podfreeze then refuses
*every* licence key -- including a correctly signed one. That is deliberate. The failure
this file exists to prevent was a check that, when its configuration was missing, accepted
anything; the replacement fails in the other direction.
"""

# 64 lowercase hex characters (32 bytes), or "" for an unconfigured build.
PUBLIC_KEY_HEX = "4c9e60e1f6f9415a1c64b9053f64c8487f76f53028dba217abce1b2072047a9b"
