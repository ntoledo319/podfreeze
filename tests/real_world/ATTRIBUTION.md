# Test fixtures

## Files authored by this project

`quoted_subspec.lock` and `legacy_specs_url.lock` were written for this test suite. They
exercise two parser behaviours that matter and are hard to find in the wild together:
a pod name quoted because it contains `+`, and the legacy
`https://github.com/cocoapods/specs.git` spelling of the central index.

## Files from real public projects

The remaining `.lock` files are unmodified `Podfile.lock` files from public repositories,
included so the parser is tested against files nobody on this project wrote. Every source
repository is MIT-licensed, and each is credited here as MIT requires:

| Fixture | Source repository | Licence |
|---|---|---|
| `HeathWang_HWPanModal.lock` | [HeathWang/HWPanModal](https://github.com/HeathWang/HWPanModal) | MIT |
| `ThasianX_SpotifyRadar.lock` | [ThasianX/SpotifyRadar](https://github.com/ThasianX/SpotifyRadar) | MIT |
| `flexlayout.lock` | [layoutBox/FlexLayout](https://github.com/layoutBox/FlexLayout) | MIT |
| `zpz1237_NirZhihuDaily2.0.lock` | [zpz1237/NirZhihuDaily2.0](https://github.com/zpz1237/NirZhihuDaily2.0) | MIT |

A `Podfile.lock` is a generated manifest rather than creative source, but "probably fine"
is not a licence. Only permissively-licensed sources are redistributed here.

A fifth fixture was previously taken from a repository with **no licence file**. No licence
means all rights reserved, so redistributing it was not clearly permitted regardless of how
mundane the content is. It was removed and replaced with `legacy_specs_url.lock`, written
from scratch, which preserves the property it was testing.

If you own one of these repositories and would prefer your lockfile not be included, open
an issue and it will be removed and replaced with an equivalent authored fixture.
