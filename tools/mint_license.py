#!/usr/bin/env python3
"""Seller-side licence minting for podfreeze. Not shipped to buyers.

This is the other half of :mod:`podfreeze.licensing`. It holds the private key; the
package ships only the public half, which is why a buyer can verify a key offline without
ever holding a secret.

    # once, ever -- creates the keypair and writes the public half into the package
    python tools/mint_license.py keygen --out ~/.podfreeze/licence-key --install

    # per sale -- prints the key and the message to send the buyer
    export PODFREEZE_LICENCE_KEY_FILE=~/.podfreeze/licence-key
    python tools/mint_license.py fulfil --tier org

    # just the key, nothing else
    python tools/mint_license.py mint --tier single

    # check what a key actually says, against the key this build ships
    python tools/mint_license.py inspect PDFZ2-...

Rules this tool enforces so they cannot be forgotten at 2am:

* the private key file is created 0600 and its contents are never printed;
* ``--out`` refuses to write inside this repository, because the repository is public;
* ``keygen`` refuses to overwrite an existing private key, because every licence already
  sold would stop verifying.

Losing the private key does not break any key already issued -- verification only needs
the public half in the package. It means no *new* key can be minted, so back it up
wherever you keep things you cannot re-derive.
"""
from __future__ import annotations

import argparse
import os
import secrets
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from podfreeze import _ed25519                      # noqa: E402
from podfreeze import __version__                    # noqa: E402
from podfreeze.licensing import (TIER_LABELS, TIERS, build_payload,  # noqa: E402
                                 check_license, encode_key)

_PUBKEY_FILE = _REPO / "podfreeze" / "_pubkey.py"


#: Where the private key lives, when it is not named on the command line. An environment
#: pointer rather than a hard-coded path: the path is machine-specific and this repository
#: is public.
KEY_FILE_ENV = "PODFREEZE_LICENCE_KEY_FILE"


def _resolve_key_file(named: str | None) -> Path:
    """The private key file: the flag, else the environment pointer, else an error."""
    chosen = named or os.environ.get(KEY_FILE_ENV)
    if not chosen:
        raise SystemExit(
            f"no private key given: pass --key-file, or set {KEY_FILE_ENV} to the file "
            f"written by `keygen`.")
    path = Path(chosen).expanduser()
    if not path.exists():
        raise SystemExit(f"{path}: no such file. Run `keygen` first, or fix "
                         f"{KEY_FILE_ENV}.")
    return path


def _read_seed(path: Path) -> bytes:
    raw = path.read_bytes().strip()
    try:
        seed = bytes.fromhex(raw.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        raise SystemExit(f"{path}: not a hex private key")
    if len(seed) != _ed25519.KEY_BYTES:
        raise SystemExit(f"{path}: expected a 32-byte key, found {len(seed)}")
    return seed


def _install_public_key(public_hex: str) -> None:
    text = _PUBKEY_FILE.read_text(encoding="utf-8")
    marker = 'PUBLIC_KEY_HEX = "'
    i = text.index(marker)
    j = text.index('"', i + len(marker))
    _PUBKEY_FILE.write_text(text[:i + len(marker)] + public_hex + text[j:],
                            encoding="utf-8")


def cmd_keygen(args: argparse.Namespace) -> int:
    out = Path(args.out).expanduser().resolve()
    try:
        out.relative_to(_REPO)
    except ValueError:
        pass
    else:
        raise SystemExit(f"refusing to write a private key inside the repository: {out}")
    if out.exists():
        raise SystemExit(
            f"{out} already exists. Overwriting it would invalidate every licence key "
            f"already sold. Move it aside deliberately if that is really the intent.")
    out.parent.mkdir(parents=True, exist_ok=True)
    seed = secrets.token_bytes(_ed25519.KEY_BYTES)
    fd = os.open(str(out), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(seed.hex().encode("ascii"))
    public_hex = _ed25519.public_key_from_seed(seed).hex()
    print(f"private key written to {out} (mode 0600, contents not printed)")
    print(f"public key: {public_hex}")
    if args.install:
        _install_public_key(public_hex)
        print(f"public key installed into {_PUBKEY_FILE.relative_to(_REPO)}")
        print("commit that file; never commit the private key")
    else:
        print(f"paste it into {_PUBKEY_FILE.relative_to(_REPO)}, or re-run with --install")
    return 0


def cmd_mint(args: argparse.Namespace) -> int:
    seed = _read_seed(_resolve_key_file(args.key_file))
    nonce = args.nonce or secrets.token_hex(4)
    payload = build_payload(args.tier, args.expires, nonce)
    key = encode_key(payload, _ed25519.sign(payload, seed))
    print(key)
    if args.verbose:
        print(f"  tier    : {args.tier}", file=sys.stderr)
        print(f"  expires : {args.expires}", file=sys.stderr)
        print(f"  nonce   : {nonce}", file=sys.stderr)
    return 0


# The words the buyer receives. Kept here, beside the minting, so that fulfilling a sale
# is one command rather than one command plus remembering what to say. It promises no
# reply time, because no reply time has been measured; it states only what is true.
_DELIVERY = """\
To: {to}
Subject: Your podfreeze {label} licence key

Thank you -- here is your podfreeze {label} licence key.

  {key}

Install or upgrade to the release that verifies this signed key (Python 3.9+):

  python3 -m pip install --upgrade "podfreeze @ git+https://github.com/ntoledo319/podfreeze@v{version}"

Use it either way:

  podfreeze {command} --license {key}

or set it once and forget it:

  export PODFREEZE_LICENSE={key}

It is verified offline against a public key shipped inside podfreeze: no account, no
activation, no phone-home. {expiry_sentence} Case and surrounding whitespace do not
matter, but every character counts -- the whole key is signed, so one dropped character
will be refused.

If it is refused, or anything in the report looks wrong, reply to this message. It will be
re-issued or refunded.

-- Toledo Technologies LLC
   hello@toledotechnologies.com
   https://github.com/ntoledo319/podfreeze
"""

_COMMANDS = {
    "single": "--pro",
    "team": "--pro",
    "org": "--audit .",
}


def cmd_fulfil(args: argparse.Namespace) -> int:
    """Mint one key for a sale and print the message that delivers it.

    A paid tier nobody can issue a key for cannot make money, and a key with no covering
    words takes a second command and a blank page at the worst moment. This is the whole
    fulfilment step.
    """
    seed = _read_seed(_resolve_key_file(args.key_file))
    nonce = args.nonce or secrets.token_hex(4)
    payload = build_payload(args.tier, args.expires, nonce)
    key = encode_key(payload, _ed25519.sign(payload, seed))

    # Verify against the key this build actually ships before anything is sent. A public
    # key that was never committed, or committed wrong, would otherwise be discovered by
    # the buyer rather than here.
    licence, reason = check_license(key, need=args.tier)
    if reason != "ok":
        raise SystemExit(
            f"refusing to send a key this build cannot verify (reason: {reason}). "
            f"The public key in podfreeze/_pubkey.py does not match this private key. "
            f"Do not send anything until that is resolved.")

    expiry_sentence = ("It does not expire." if args.expires == "never"
                       else f"It is valid through {args.expires} (inclusive).")
    print(_DELIVERY.format(to=args.to, label=TIER_LABELS[args.tier], key=key,
                           command=_COMMANDS[args.tier], version=__version__,
                           expiry_sentence=expiry_sentence))
    print(f"--- minted and verified: tier={args.tier} expires={args.expires} "
          f"nonce={nonce} ---", file=sys.stderr)
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    licence, reason = check_license(args.key, need=args.need)
    print(f"reason: {reason}")
    if licence is not None:
        print(f"tier   : {licence.tier} ({licence.label})")
        print(f"expires: {licence.expires}")
        print(f"nonce  : {licence.nonce}")
    return 0 if reason == "ok" else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mint_license", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    g = sub.add_parser("keygen", help="create the seller keypair (once, ever)")
    g.add_argument("--out", required=True, help="where to write the private key")
    g.add_argument("--install", action="store_true",
                   help="write the public half into podfreeze/_pubkey.py")
    g.set_defaults(func=cmd_keygen)

    m = sub.add_parser("mint", help="sign one licence key")
    m.add_argument("--key-file", default=None,
                   help=f"the private key from keygen (default: ${KEY_FILE_ENV})")
    m.add_argument("--tier", required=True, choices=sorted(TIERS, key=TIERS.get))
    m.add_argument("--expires", default="never",
                   help="ISO date, or 'never' (default) -- the storefront sells a "
                        "permanent licence, so 'never' is the normal answer")
    m.add_argument("--nonce", default=None,
                   help="8-32 lowercase hex characters; random if omitted")
    m.add_argument("--verbose", action="store_true",
                   help="also print the tier, expiry and nonce to stderr")
    m.set_defaults(func=cmd_mint)

    f = sub.add_parser("fulfil", help="mint one key for a sale and print the "
                                      "message that delivers it")
    f.add_argument("--tier", required=True, choices=sorted(TIERS, key=TIERS.get))
    f.add_argument("--to", default="<the address on the Stripe receipt>",
                   help="the buyer's email address, for the To: line")
    f.add_argument("--key-file", default=None,
                   help=f"the private key from keygen (default: ${KEY_FILE_ENV})")
    f.add_argument("--expires", default="never",
                   help="ISO date, or 'never' (default) -- the storefront sells a "
                        "permanent licence")
    f.add_argument("--nonce", default=None,
                   help="8-32 lowercase hex characters; random if omitted")
    f.set_defaults(func=cmd_fulfil)

    i = sub.add_parser("inspect", help="verify a key against this build's public key")
    i.add_argument("key")
    i.add_argument("--need", default="single", choices=sorted(TIERS, key=TIERS.get))
    i.set_defaults(func=cmd_inspect)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
