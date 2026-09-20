"""Licence verification tests.

The defect these exist to prevent
---------------------------------
``verify_license`` used to fall back to ``len(payload) >= 8 and len(sig) >= 8``
whenever ``PODFREEZE_SECRET`` was unset -- which is every buyer's machine, always, because
that variable is the seller's. ``PDFZ1-AAAAAAAA-BBBBBBBB`` verified. And because the check
returned a bare bool, the US$499 ``--audit`` and the US$29 ``--pro`` consulted the same
answer, so one fabricated string opened both.

The 142-test suite at the time did not catch any of it: every "bad key" it tested was
malformed in *shape*, so every one of them would have been refused by a check that did
nothing but look at shape. The tests below are the ones that were missing -- a
well-formed-but-unsigned key must be refused, and a cheaper tier must not open a dearer
command.
"""
from __future__ import annotations

import binascii
import datetime as dt
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from podfreeze import _ed25519                                       # noqa: E402
from podfreeze import licensing as lic                               # noqa: E402
from tests import minting                                            # noqa: E402


# --- the signature primitive itself ----------------------------------------
# RFC 8032 section 7.1. If the maths is wrong, everything above it is theatre, so the
# implementation is checked against the standard's own vectors rather than against itself.
RFC8032_VECTORS = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb882"
     "1590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1"
     "e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b"
     "538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


@pytest.mark.parametrize("seed_hex,pub_hex,msg_hex,sig_hex", RFC8032_VECTORS)
def test_ed25519_matches_rfc8032(seed_hex, pub_hex, msg_hex, sig_hex):
    h = binascii.unhexlify
    assert _ed25519.public_key_from_seed(h(seed_hex)) == h(pub_hex)
    assert _ed25519.sign(h(msg_hex), h(seed_hex)) == h(sig_hex)
    assert _ed25519.verify(h(msg_hex), h(sig_hex), h(pub_hex))


def test_ed25519_rejects_every_single_bit_flip():
    """A signature that verifies after being altered is not a signature."""
    seed, msg = minting.SEED, b"podfreeze|v2|org|never|0123abcd"
    pub = _ed25519.public_key_from_seed(seed)
    sig = _ed25519.sign(msg, seed)
    assert _ed25519.verify(msg, sig, pub)
    for i in (0, 31, 32, 63):
        broken = bytearray(sig)
        broken[i] ^= 0x01
        assert not _ed25519.verify(msg, bytes(broken), pub), f"byte {i} flip still verified"
    assert not _ed25519.verify(msg + b"!", sig, pub), "message tampering still verified"
    assert not _ed25519.verify(
        msg, sig, _ed25519.public_key_from_seed(minting.OTHER_SEED)
    ), "a different signer's public key verified this signature"


def test_ed25519_rejects_malformed_input():
    pub = _ed25519.public_key_from_seed(minting.SEED)
    assert not _ed25519.verify(b"x", b"", pub)
    assert not _ed25519.verify(b"x", b"\x00" * 63, pub)
    assert not _ed25519.verify(b"x", b"\x00" * 64, b"")
    # A non-canonical S (>= the group order) must be refused rather than reduced.
    sig = bytearray(_ed25519.sign(b"x", minting.SEED))
    sig[32:] = (2 ** 253).to_bytes(32, "little")
    assert not _ed25519.verify(b"x", bytes(sig), pub)


# --- the defect, as a test -------------------------------------------------
FORGERIES_THAT_USED_TO_WORK = [
    "PDFZ1-AAAAAAAA-BBBBBBBB",
    "PDFZ1-00000000-00000000",
    "PDFZ1-NOTAREALKEY-NOTAREALSIG",
    "PDFZ1-O110FBF11EE4-69DEE505AB1993B2",
]


@pytest.mark.parametrize("key", FORGERIES_THAT_USED_TO_WORK)
def test_fabricated_keys_are_refused(key):
    """These four strings verified on every buyer's machine before this change."""
    assert lic.verify_license(key, public_key=minting.PUBLIC_HEX) is None, (
        f"{key} verified as a paid licence")


def test_well_formed_but_unsigned_key_is_refused():
    """The test that was missing.

    Every "bad key" in the old suite was malformed in shape, so a check that only looked
    at shape passed the suite. This key has a correct prefix, a correct payload, a
    correct-length signature and a plausible tier -- everything except a real signature.
    """
    key = minting.unsigned(tier="org")
    parts = key.split("-")
    assert parts[0] == lic.KEY_PREFIX and len(parts) == 3, "fixture is not well formed"
    licence, reason = lic.check_license(key, public_key=minting.PUBLIC_HEX)
    assert licence is None
    assert reason == lic.BAD_SIGNATURE, (
        "a well-formed key with no signature was not refused for its signature")


def test_a_signature_from_another_keypair_is_refused():
    key = minting.mint(tier="org", seed=minting.OTHER_SEED)
    assert lic.verify_license(key, public_key=minting.PUBLIC_HEX) is None


def test_editing_the_tier_inside_a_real_key_invalidates_it():
    """The tier is inside the signed bytes, so it cannot be upgraded by hand."""
    import base64

    single = minting.mint(tier="single")
    assert lic.verify_license(single, public_key=minting.PUBLIC_HEX) is not None
    prefix, payload_b32, sig_b32 = single.split("-")
    payload = base64.b32decode(payload_b32 + "=" * ((-len(payload_b32)) % 8), casefold=True)
    upgraded = payload.replace(b"|single|", b"|org|")
    assert upgraded != payload
    forged = lic.encode_key(upgraded, base64.b32decode(
        sig_b32 + "=" * ((-len(sig_b32)) % 8), casefold=True))
    assert lic.verify_license(forged, public_key=minting.PUBLIC_HEX) is None, (
        "a buyer could promote a US$29 key to a US$499 key by editing it")


# --- tiers -----------------------------------------------------------------
def test_a_single_project_key_does_not_unlock_the_organisation_audit():
    key = minting.mint(tier="single")
    ok, reason = lic.check_license(key, need="single", public_key=minting.PUBLIC_HEX)
    assert reason == lic.OK and ok.tier == "single"
    refused, reason = lic.check_license(key, need="org", public_key=minting.PUBLIC_HEX)
    assert reason == lic.TIER_TOO_LOW, "the US$29 key opened the US$499 command"
    assert refused is not None and refused.tier == "single"


def test_an_organisation_key_opens_everything_below_it():
    key = minting.mint(tier="org")
    for need in ("single", "team", "org"):
        licence, reason = lic.check_license(key, need=need,
                                            public_key=minting.PUBLIC_HEX)
        assert reason == lic.OK, f"an organisation key was refused for {need}"
        assert licence.tier == "org"


def test_a_team_key_sits_between_the_two():
    key = minting.mint(tier="team")
    assert lic.check_license(key, need="single",
                             public_key=minting.PUBLIC_HEX)[1] == lic.OK
    assert lic.check_license(key, need="org",
                             public_key=minting.PUBLIC_HEX)[1] == lic.TIER_TOO_LOW


# --- expiry ----------------------------------------------------------------
def test_an_expired_key_is_refused_and_says_so():
    key = minting.mint(tier="org", expires="2020-01-01")
    licence, reason = lic.check_license(key, public_key=minting.PUBLIC_HEX)
    assert reason == lic.EXPIRED and licence is None


def test_a_dated_key_is_valid_up_to_and_including_its_last_day():
    key = minting.mint(tier="single", expires="2026-12-31")
    assert lic.check_license(key, public_key=minting.PUBLIC_HEX,
                             today=dt.date(2026, 12, 31))[1] == lic.OK
    assert lic.check_license(key, public_key=minting.PUBLIC_HEX,
                             today=dt.date(2027, 1, 1))[1] == lic.EXPIRED


def test_the_normal_key_never_expires():
    """The storefront sells a permanent licence. A key that quietly died would be a lie."""
    key = minting.mint(tier="single")
    assert lic.check_license(key, public_key=minting.PUBLIC_HEX,
                             today=dt.date(2099, 1, 1))[1] == lic.OK


# --- fail closed -----------------------------------------------------------
def test_a_build_with_no_public_key_refuses_even_a_genuine_key():
    """The opposite of the original bug: missing configuration must refuse, not accept."""
    key = minting.mint(tier="org")
    licence, reason = lic.check_license(key, public_key="")
    assert licence is None and reason == lic.UNCONFIGURED


def test_the_public_key_cannot_be_overridden_from_the_environment(monkeypatch):
    """An env override would let anyone install their own key and mint their own licences."""
    key = minting.mint(tier="org", seed=minting.OTHER_SEED)
    for name in ("PODFREEZE_PUBKEY", "PODFREEZE_PUBLIC_KEY", "PODFREEZE_SECRET"):
        monkeypatch.setenv(name, minting.OTHER_PUBLIC_HEX)
    assert lic.verify_license(key, public_key=minting.PUBLIC_HEX) is None


def test_a_secret_on_the_machine_changes_nothing(monkeypatch):
    """PODFREEZE_SECRET was the variable whose absence opened the gate. It is now inert."""
    monkeypatch.setenv("PODFREEZE_SECRET", "anything-at-all")
    assert lic.verify_license("PDFZ1-AAAAAAAA-BBBBBBBB",
                              public_key=minting.PUBLIC_HEX) is None
    assert lic.verify_license(minting.mint(), public_key=minting.PUBLIC_HEX) is not None


# --- paste tolerance, kept ---------------------------------------------------
def test_a_real_key_survives_how_people_actually_paste(monkeypatch):
    key = minting.mint(tier="team")
    for variant in (key, f"  {key}  ", key.lower(), f"\t{key.lower()}\n"):
        licence = lic.verify_license(variant, public_key=minting.PUBLIC_HEX)
        assert licence is not None, f"a paying buyer was locked out by {variant!r}"
        assert licence.tier == "team"


def test_the_key_is_read_from_the_environment_when_not_passed(monkeypatch):
    monkeypatch.setenv("PODFREEZE_LICENSE", minting.mint(tier="org"))
    assert lic.verify_license(public_key=minting.PUBLIC_HEX).tier == "org"


# --- shape refusals, still refused -------------------------------------------
@pytest.mark.parametrize("key", [
    "", "   ", "garbage", "PDFZ2", "PDFZ2-short-x", "PDFZ2-AAAA",
    "PDFZ2-AAAAAAAA-BBBBBBBB-CCCCCCCC", "PDFZ3-AAAAAAAA-BBBBBBBB",
    "PDFZ2-!!!!!!!!-????????",
])
def test_malformed_keys_are_refused(key):
    assert lic.verify_license(key, public_key=minting.PUBLIC_HEX) is None


def test_a_key_signed_for_another_product_cannot_be_replayed():
    """The product name is inside the signed bytes."""
    payload = b"someotherproduct|v2|org|never|0123abcd"
    key = lic.encode_key(payload, _ed25519.sign(payload, minting.SEED))
    assert lic.verify_license(key, public_key=minting.PUBLIC_HEX) is None


def test_no_secret_is_needed_to_verify():
    """The whole point: a buyer's machine verifies with public data only.

    Checked against the executable code with every docstring and comment stripped, so
    that describing the old design in prose -- which this module deliberately does --
    cannot be mistaken for still running it.
    """
    import ast
    import inspect

    from podfreeze import cli, pro

    for module in (lic, pro, cli):
        tree = ast.parse(inspect.getsource(module))
        for node in ast.walk(tree):
            body = getattr(node, "body", None)
            if (isinstance(body, list) and body and isinstance(body[0], ast.Expr)
                    and isinstance(getattr(body[0], "value", None), ast.Constant)
                    and isinstance(body[0].value.value, str)):
                body.pop(0)
        code = ast.unparse(tree)
        assert "hmac" not in code, f"a symmetric check crept back into {module.__name__}"
        assert "PODFREEZE_SECRET" not in code, (
            f"{module.__name__} reads the seller secret again")


# --- the tiers, through the CLI a buyer actually types -----------------------
def _two_project_tree(tmp_path):
    lock = ("PODS:\n  - Alamofire (5.8.1)\n\nDEPENDENCIES:\n  - Alamofire\n\n"
            "SPEC REPOS:\n  trunk:\n    - Alamofire\n\nCOCOAPODS: 1.15.2\n")
    for name in ("AppOne", "AppTwo"):
        proj = tmp_path / name
        proj.mkdir()
        (proj / "Podfile.lock").write_text(lock, encoding="utf-8")
    return tmp_path


@pytest.fixture()
def configured(monkeypatch):
    """A build carrying this session's public key, and an offline trunk lookup."""
    from podfreeze import audit as audit_mod
    from podfreeze.enrich import Enrichment

    from podfreeze import pro as pro_mod

    def _offline(names, workers=8):
        return [Enrichment(pod=n, latest_version="5.9.1",
                           latest_published="2024-03-31", total_versions=42,
                           swiftpm_available=True, swiftpm_repo="Alamofire/Alamofire",
                           error=None) for n in names]

    monkeypatch.setattr(lic, "PUBLIC_KEY_HEX", minting.PUBLIC_HEX)
    monkeypatch.delenv("PODFREEZE_LICENSE", raising=False)
    # No test in this file may reach the network: a licence gate that only holds while
    # trunk.cocoapods.org answers is not a licence gate.
    monkeypatch.setattr(audit_mod, "enrich", _offline)
    monkeypatch.setattr(pro_mod, "enrich", _offline)
    return None


def test_cli_audit_refuses_a_single_project_key_and_writes_nothing(tmp_path, capsys,
                                                                   configured):
    """The US$499 deliverable, asked for with a US$29 key.

    Previously this exited 0 and wrote the complete organisation report.
    """
    from podfreeze.cli import main

    root = _two_project_tree(tmp_path)
    out = tmp_path / "audit.md"
    rc = main(["--audit", str(root), "--out", str(out),
               "--license", minting.mint(tier="single")])
    err = capsys.readouterr().err
    assert rc == 4, "a single-project key produced the organisation audit"
    assert not out.exists(), "a refused audit still wrote the paid report to disk"
    assert "HIGHER TIER" in err.upper()


def test_cli_audit_refuses_a_team_key(tmp_path, capsys, configured):
    from podfreeze.cli import main

    out = tmp_path / "audit.md"
    rc = main(["--audit", str(_two_project_tree(tmp_path)), "--out", str(out),
               "--license", minting.mint(tier="team")])
    assert rc == 4 and not out.exists()


def test_cli_audit_refuses_a_forged_key_and_writes_nothing(tmp_path, capsys, configured):
    from podfreeze.cli import main

    out = tmp_path / "audit.md"
    rc = main(["--audit", str(_two_project_tree(tmp_path)), "--out", str(out),
               "--license", "PDFZ1-AAAAAAAA-BBBBBBBB"])
    assert rc == 4, "the fabricated key from the teardown still produced the audit"
    assert not out.exists()


def test_cli_audit_runs_for_an_organisation_key(tmp_path, capsys, configured):
    from podfreeze.cli import main

    root = _two_project_tree(tmp_path)
    out = tmp_path / "audit.md"
    rc = main(["--audit", str(root), "--out", str(out),
               "--license", minting.mint(tier="org")])
    stdout = capsys.readouterr().out
    assert rc == 0, "a genuine organisation key was refused"
    assert out.exists() and out.stat().st_size > 0
    assert "licence tier: organisation audit" in stdout


def test_cli_pro_runs_for_a_single_project_key(tmp_path, capsys, configured):
    """--pro is the US$29 command: the cheapest paid tier must open it."""
    from podfreeze.cli import main

    lock = tmp_path / "Podfile.lock"
    lock.write_text("PODS:\n  - Alamofire (5.8.1)\n\nDEPENDENCIES:\n  - Alamofire\n\n"
                    "SPEC REPOS:\n  trunk:\n    - Alamofire\n\nCOCOAPODS: 1.15.2\n")
    rc = main(["--pro", str(lock), "--license", minting.mint(tier="single")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "PRO — migration plan" in out
    assert "NOT RECOGNISED" not in out
    assert "ORDER OF WORK" in out, "the paid section did not render for a paid key"


def test_cli_pro_refuses_a_forged_key(tmp_path, capsys, configured):
    from podfreeze.cli import main

    lock = tmp_path / "Podfile.lock"
    lock.write_text("PODS:\n  - Alamofire (5.8.1)\n\nDEPENDENCIES:\n  - Alamofire\n\n"
                    "SPEC REPOS:\n  trunk:\n    - Alamofire\n\nCOCOAPODS: 1.15.2\n")
    main(["--pro", str(lock), "--license", "PDFZ1-NOTAREALKEY-NOTAREALSIG"])
    out = capsys.readouterr().out
    assert "LICENCE KEY NOT RECOGNISED" in out
    assert "ORDER OF WORK" not in out, "a fabricated key still rendered the paid plan"


# --- the shipped configuration ----------------------------------------------
def test_the_shipped_public_key_is_either_absent_or_usable():
    """A mistyped public key must not look like a working one.

    An empty value is a legitimate development state and fails closed. A non-empty value
    that is not 32 bytes of hex would also fail closed, but silently, and the seller would
    only learn about it from a buyer whose key does not work.
    """
    from podfreeze._pubkey import PUBLIC_KEY_HEX

    if not PUBLIC_KEY_HEX:
        pytest.skip("this build ships no seller public key; it refuses every key")
    assert len(PUBLIC_KEY_HEX) == 64, "a public key is 64 hex characters"
    raw = binascii.unhexlify(PUBLIC_KEY_HEX)
    assert len(raw) == _ed25519.KEY_BYTES
    assert lic._public_key_bytes(None) == raw, "the shipped key does not load"


# --- being able to sell at all ----------------------------------------------
# The signature check above is correct and, with no seller public key committed, it
# refuses every key ever minted -- including the one a buyer just paid for. Correct and
# unsellable is still unsellable, and the failure is invisible from the seller's side:
# the storefront takes the payment, and only the buyer sees the refusal. These are the
# tests that would have caught that.
def test_the_shipped_build_can_verify_a_key_at_all():
    """A release with an empty public key cannot fulfil a single sale.

    ``test_the_shipped_public_key_is_either_absent_or_usable`` accepts the empty value as
    a development state. This one does not: a build that reaches a buyer must be able to
    accept the key that buyer was sent.
    """
    from podfreeze._pubkey import PUBLIC_KEY_HEX

    assert PUBLIC_KEY_HEX, (
        "podfreeze/_pubkey.py carries no seller public key, so this build refuses every "
        "licence key including a valid one; run `tools/mint_license.py keygen --install`")
    assert lic._public_key_bytes(None) is not None, "the shipped public key does not load"


def test_a_key_signed_by_the_wrong_private_key_is_refused_by_the_shipped_build():
    """The committed public key is the one being used, not a leftover test key."""
    licence, reason = lic.check_license(minting.mint(tier="org"), need="org")
    assert reason == lic.BAD_SIGNATURE, (
        "a key signed by a throwaway keypair verified against the shipped public key")
    assert licence is None


def test_fulfil_refuses_to_print_a_key_the_shipped_build_would_reject(tmp_path):
    """The mismatch is caught before the email, not by the buyer.

    If the private key on the seller's disk is not the partner of the public key in
    ``_pubkey.py``, every key minted from it is dead on arrival. ``fulfil`` verifies what
    it minted against the shipped key and prints nothing when that fails.
    """
    import subprocess

    key_file = tmp_path / "wrong-key"
    key_file.write_text(binascii.hexlify(bytes(minting.OTHER_SEED)).decode("ascii"))
    proc = subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parents[1] / "tools" /
                             "mint_license.py"), "fulfil", "--tier", "org",
         "--key-file", str(key_file)],
        capture_output=True, text=True)
    assert proc.returncode != 0, "a key this build cannot verify was fulfilled anyway"
    assert lic.KEY_PREFIX not in proc.stdout, "an unusable key was printed to send"
    assert "does not match" in proc.stderr


# --- what the buyer is told about delivery ----------------------------------
# The storefront said the key appeared on the Stripe confirmation page. Nothing ever put
# it there: keys are minted by hand and emailed. A buyer who believes the page will show
# them a key does not go looking in their inbox, and concludes they were charged for
# nothing.
def test_the_storefront_does_not_promise_a_key_on_the_confirmation_page():
    html = (Path(__file__).resolve().parents[1] / "docs" / "index.html").read_text(
        encoding="utf-8")
    lowered = " ".join(html.lower().split())
    assert "appears on the" not in lowered and "no email required" not in lowered, (
        "the storefront still promises the key on the confirmation page")
    assert "hello@toledotechnologies.com" in lowered, (
        "the storefront names no address a buyer can chase a missing key at")


def test_the_refusal_message_sends_a_buyer_to_the_right_place():
    from podfreeze import pro

    lines = " ".join(pro.licence_problem_lines(lic.BAD_SIGNATURE))
    assert "Stripe confirmation" not in lines, (
        "the CLI still tells a buyer to look on a page that never held their key")
    assert pro.SUPPORT_EMAIL in lines
