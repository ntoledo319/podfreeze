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
pip install "podfreeze @ git+https://github.com/ntoledo319/podfreeze@v0.8.5"
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
      - uses: ntoledo319/podfreeze@v0.8.5
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
      - uses: ntoledo319/podfreeze@v0.8.5
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

| | |
|---|---|
| **Single project** — $29 | [Buy](https://buy.stripe.com/dRm8wP4nY8pi2l5aZe87K0r) |
| **Team / unlimited projects + CI** — $199 | [Buy](https://buy.stripe.com/4gM9AT2fQdJC9Nx4AQ87K0s) |
| **Organisation audit** — $499 | [Buy](https://buy.stripe.com/8x26oHbQqdJCe3Ngjy87K0t) |

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

Licence keys verify **offline**. No phone-home, no telemetry, no account. Works
air-gapped.

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

## Tests

```
pip install -e ".[dev]"
python -m pytest tests -q
```

The suite includes a **census test** pinning the exact expected finding set across every
input form at once — so a change that silently detects *less* fails loudly, instead of
producing a smaller report that still looks credible.

## License

MIT — see [LICENSE](LICENSE).
