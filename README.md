# podfreeze

Find which of your CocoaPods dependencies can never receive another published
security patch after the trunk freeze.

```
pip install podfreeze
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
