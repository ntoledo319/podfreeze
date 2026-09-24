# podfreeze

Find which of your CocoaPods dependencies can never receive another published
published version — including a security fix — after the trunk freeze.

**[→ Check your Podfile.lock in the browser](https://ntoledo319.github.io/podfreeze/check.html)** — no install, nothing uploaded.

I ran this across **83 real public iOS projects**: 96% of those whose dependency sources
could be determined had at least one pod that can never receive another published version.
Firebase pods dominate the exposed set — and
[Firebase stops publishing to CocoaPods in October 2026](https://firebase.google.com/docs/ios/cocoapods-deprecation),
two months before the trunk freeze.
**[Full findings and method →](https://ntoledo319.github.io/podfreeze/findings.html)**
([raw data, CC0](https://ntoledo319.github.io/podfreeze/findings.json) · [reproduce it](reproduce_findings.py))

Or run it locally:

```
pip install "podfreeze @ git+https://github.com/ntoledo319/podfreeze@v0.8.6"
cd your-ios-project
podfreeze
```

No signup, no account, no data leaves your machine. It reads `Podfile.lock` and prints.

## What's actually happening

On **2 December 2026**, CocoaPods trunk stops accepting new podspecs, permanently.
A read-only test run is scheduled for **1–7 November 2026**. This is the maintainer's
own plan, announced on the CocoaPods blog:
<https://blog.cocoapods.org/CocoaPods-Specs-Repo/>

**Your build does not break.** That is the first thing this tool tells you, because it
is true and most coverage of this gets it wrong. Existing versions keep resolving from
the Specs repo on GitHub and the CDN on jsDelivr. A Podfile that resolves today resolves
identically after the freeze.

What changes is narrower, and it is a supply-chain question rather than a build question:

> after the freeze, a library with a newly discovered critical CVE **has no canonical
> version to carry the fix**, and every consumer is left pinning a git fork by hand.

So the question worth answering before December is: *which of my pods are pinned to
coordinates that can never receive a patch?*

## What it does

`podfreeze` reads the `SPEC REPOS:` section of your lockfile — the field that records
where each pod actually resolved from — and separates:

- **trunk** — affected. No future published version can reach this coordinate.
- **private spec repo** — insulated. You control the index.
- **git / path / podspec pin** — insulated. Bypasses trunk entirely.

That distinction is the whole point. The CocoaPods announcement says the freeze
*"shouldn't affect people who use CocoaPods with their own specs repos, or have all of
their dependencies vendored"* — so a scanner that ignores `SPEC REPOS` raises false
alarms against exactly the teams who already did the right thing.

### Example

```
$ podfreeze

podfreeze 0.1.0 — CocoaPods trunk freeze exposure
file: Podfile.lock
lockfile written by CocoaPods 1.15.2

examined 4 pod(s)
spec repos declared: https://github.internal.example/ios/Specs.git, trunk

  2 pod(s) resolve from CocoaPods trunk:

    - Alamofire 5.8.1
    - SDWebImage 5.18.10

  2 pod(s) already insulated from the freeze:

    - InternalAuth: resolves from private spec repo https://github.internal.example/ios/Specs.git
    - LocalKit: pinned via EXTERNAL SOURCES (:path); bypasses trunk
```

`--json` gives machine-readable output for CI.

## Use it in CI

The GitHub Action is free and needs no licence key. It fails the build only if you ask
it to:

```yaml
name: podfreeze
on: [pull_request]

jobs:
  cocoapods-freeze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ntoledo319/podfreeze@v0.8.6
        with:
          path: Podfile.lock
          fail-on-exposed: 'false'   # 'true' to block the PR on any trunk-resolved pod
```

Inputs:

| input | default | meaning |
|---|---|---|
| `path` | `Podfile.lock` | lockfile, or a directory containing one |
| `fail-on-exposed` | `false` | exit non-zero if any pod resolves from trunk |
| `fail-on-undetermined` | `false` | exit non-zero if any pod's source **could not be determined** — a lockfile predating `SPEC REPOS` reports 0 exposed and would otherwise pass silently |
| `comment-on-pr` | `false` | post the report as a PR comment (needs `pull-requests: write`) |
| `license` | *(empty)* | Pro licence key — enables the `--pro` migration plan |

Outputs: `exposed-count`, `examined-count`, `undetermined-count`, `report-path`.

With a Pro key, pass it from a secret to get the prioritised migration plan in CI:

```yaml
      - uses: ntoledo319/podfreeze@v0.8.6
        with:
          license: ${{ secrets.PODFREEZE_LICENSE }}
```

A note on `fail-on-exposed`: most projects should leave it `false` at first. The freeze
does not break your build, so blocking every PR on day one is noise. Turn it on once
you have migrated the pods you intend to migrate, to stop new trunk dependencies
appearing.

## Pro

The free tool tells you **which** pods are exposed. Pro tells you **what to do about
each one, and in what order** — using live data, not guesses.

For every exposed pod it fetches from the CocoaPods trunk API:

- the latest version actually published, and **the date it was published**
- how long the pod has been static (SDWebImage's last trunk release was **2020**)
- whether a **`Package.swift` exists** to migrate to
- a ranked order of work — the pods still shipping releases come first, because
  those are the ones losing a live update channel at the freeze

```
$ podfreeze --pro

    SDWebImage
      in your lockfile : 5.18.10
      latest on trunk  : 5.9.5 (published 2020-11-13)
      assessment       : last published 5y ago — effectively frozen already
      SwiftPM          : Package.swift found at SDWebImage/SDWebImage
```

| Tier | Unlocks | |
|---|---|---|
| **Single project** — $29 | `--pro` on one project | [Buy](https://buy.stripe.com/dRm8wP4nY8pi2l5aZe87K0r) |
| **Team / unlimited projects + CI** — $199 | `--pro` on any number of projects, and in CI | [Buy](https://buy.stripe.com/4gM9AT2fQdJC9Nx4AQ87K0s) |
| **Organisation audit** — $499 | `--pro`, plus `--audit` across a whole tree | [Buy](https://buy.stripe.com/8x26oHbQqdJCe3Ngjy87K0t) |

The tier is signed into the key, so `--audit` requires an organisation key and refuses a
cheaper one. **Single and Team unlock the same command**; what differs between them is how
many projects and developers the licence covers, which is a licensing difference, not a
technical one. That is said here rather than left to be discovered after payment.

### Organisation audit — `--audit`

For a codebase with more than one app. Scans **every** `Podfile.lock` under a directory
and writes a dated migration report:

```
$ podfreeze --audit ~/code --out audit.md
podfreeze audit: scanned 4 Podfile.lock file(s) under /Users/you/code
  2 project(s) with trunk exposure
  3 distinct exposed pod(s)
  report written to audit.md
```

The report contains a **blast-radius table** — which of your apps each exposed pod
appears in — ranked by what you actually lose at the freeze:

| Pod | Last published | Static for | Your projects affected | SwiftPM target |
|---|---|---|---|---|
| `SDWebImage` | 5.9.5 (2020-11-13) | 5.8 years | 1 — app-consumer | yes |
| `Realm` | 5.5.1 (2021-03-18) | 5.5 years | 1 — app-enterprise | not at conventional path |
| `Alamofire` | 5.9.1 (2024-03-31) | 2.5 years | 1 — app-consumer | yes |

Every figure is derived from your lockfiles and the CocoaPods trunk API. There are no
invented effort estimates, no severity scores, and no risk theatre. Files that cannot be
parsed are **listed in the report**, never silently skipped — a skipped file and a clean
file must not look the same.

### How licence keys work, and what the check is worth

A key looks like `PDFZ2-<payload>-<signature>`. The payload says which tier it is and when
it expires; the signature is **Ed25519** over exactly those bytes. Your copy of podfreeze
ships the seller's *public* key and verifies the signature with it.

That means:

- **Offline.** No phone-home, no telemetry, no account, no activation server. Works
  air-gapped, and podfreeze never learns that you ran it.
- **No secret on your machine.** Verification needs public data only. Earlier builds checked
  the key with an HMAC keyed with a secret only the seller had — so on every buyer's machine
  it silently degraded to checking that the key was *long enough*, and any string shaped
  like a key passed. That is fixed: the signature is now actually checked, and a key that
  was not signed by the seller is refused.
- **The tier cannot be edited.** It is inside the signed bytes, so changing `single` to
  `org` invalidates the signature.
- **Keys are long**, around 160 characters, because a real signature is 64 bytes. Case and
  surrounding whitespace do not matter; paste the whole thing.

**And the honest part.** podfreeze is MIT licensed and its source is public. Anyone willing
to edit `licensing.py` can delete the check — a signature makes a *forged* key impossible,
it cannot make a *patched copy* impossible, and no client-side check in an open-source
package ever can. The licence is enforced against mistakes and casual sharing, and beyond
that it runs on trust. If that trade is not acceptable to you, the free tier is complete,
un-crippled and not time-limited, and you are welcome to stay on it.

### What Pro deliberately does NOT include

**No CVE data.** There is no vulnerability database for the CocoaPods ecosystem —
verified directly: OSV.dev returns `{"code":3,"message":"invalid ecosystem"}` for
`CocoaPods`, and GitHub's advisory API answers `422: cocoapods is not a possible
value`. Matching pod names against GitHub's `swift` ecosystem (which indexes SwiftPM
packages like `apple/swift-nio`) returns near-universal "no advisories" — a broken
lookup that is indistinguishable from a clean result.

Any tool claiming per-pod CVE scanning for CocoaPods is worth questioning closely.

## Honest limitations

- Lockfiles written by **CocoaPods < 1.7** have no `SPEC REPOS` section. Those pods are
  reported as `unknown`, **not** guessed as exposed. Re-run `pod install` on a modern
  CocoaPods for an exact answer.
- A parse failure **exits 3 with an error**. It never prints a clean report, because
  "found nothing" and "couldn't read the file" must not look identical.
- It reports exposure. It does not migrate anything for you.
- It does not phone home, and it has no telemetry.
- The Pro licence check is a signature, not a copy-protection system. The package is MIT
  licensed and the check is a few lines of readable Python; see
  [How licence keys work](#how-licence-keys-work-and-what-the-check-is-worth).

## Tests

```
pip install -e ".[dev]"
python -m pytest tests -q
```

The suite includes a **census test** pinning the exact expected finding set across every
input form at once — so a change that silently detects *less* fails loudly, instead of
producing a smaller report that still looks credible.

## Selling Pro (seller only)

Keys are signed offline with a private key that never enters this repository and never
reaches a buyer. `podfreeze/_pubkey.py` carries only the public half.

**Once, ever** — create the keypair. A build whose `_pubkey.py` is empty **refuses every
licence key, including a valid one**, so this has to exist before a single sale can be
fulfilled:

```
python tools/mint_license.py keygen --out ~/.podfreeze/licence-key --install
```

`keygen` writes the private key outside the repository at mode 0600 and never prints it;
`--install` writes only the public half into `podfreeze/_pubkey.py`. Commit that file.
Keep the private key backed up: without it no *new* key can be minted, though every key
already issued keeps working, because verification only ever needed the public half.

**Per sale** — point the tool at the private key once per shell, then one command per
payment:

```
export PODFREEZE_LICENCE_KEY_FILE=~/.podfreeze/licence-key

python tools/mint_license.py fulfil --tier single --to buyer@example.com   # $29
python tools/mint_license.py fulfil --tier team   --to buyer@example.com   # $199
python tools/mint_license.py fulfil --tier org    --to buyer@example.com   # $499
```

`fulfil` mints the key, verifies it against the public key this build actually ships —
refusing to print anything if the two halves do not match, so a mismatch is found here
rather than by the buyer — and prints the delivery email ready to send. Tier comes from
what they paid for; the Stripe receipt has the address.

`mint` prints a bare key with no covering message, and `inspect <key>` says what a key
claims and whether this build accepts it.

## License

MIT — see [LICENSE](LICENSE).
