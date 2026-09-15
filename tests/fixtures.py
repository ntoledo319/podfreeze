"""Test fixtures — written from scratch for this tool.

Every fixture here was authored by hand to exercise one input form. None is copied from
any real project. The census test pins the EXACT expected finding set across all forms
at once, so a change that silently stops detecting one form fails loudly instead of
quietly reporting fewer findings.
"""

# Modern lockfile: trunk pods, a private spec repo, subspecs, and an external git pin.
MIXED = """
PODS:
  - Alamofire (5.8.1)
  - SDWebImage (5.18.10):
    - SDWebImage/Core (= 5.18.10)
  - SDWebImage/Core (5.18.10)
  - InternalAuth (2.1.0)
  - LocalKit (0.9.0)

DEPENDENCIES:
  - Alamofire (~> 5.8)
  - SDWebImage
  - InternalAuth
  - LocalKit (from `../LocalKit`)

SPEC REPOS:
  trunk:
    - Alamofire
    - SDWebImage
  https://github.internal.example/ios/Specs.git:
    - InternalAuth

EXTERNAL SOURCES:
  LocalKit:
    :path: "../LocalKit"

COCOAPODS: 1.15.2
"""

# Legacy lockfile: no SPEC REPOS section at all (CocoaPods < 1.7).
LEGACY_NO_SPEC_REPOS = """
PODS:
  - AFNetworking (3.2.1)
  - Mantle (2.1.0)

DEPENDENCIES:
  - AFNetworking
  - Mantle

COCOAPODS: 1.5.3
"""

# Everything insulated: git tag pin + private repo. Must report ZERO trunk exposure.
FULLY_INSULATED = """
PODS:
  - VendoredCrypto (1.0.0)
  - ForkedLib (3.3.3)

DEPENDENCIES:
  - VendoredCrypto (from `https://git.example/vendored.git`, tag `1.0.0`)
  - ForkedLib

SPEC REPOS:
  https://github.internal.example/Specs.git:
    - ForkedLib

EXTERNAL SOURCES:
  VendoredCrypto:
    :git: "https://git.example/vendored.git"
    :tag: "1.0.0"

COCOAPODS: 1.14.3
"""

# CDN-style spec repo key, which must be recognised as trunk.
CDN_KEY = """
PODS:
  - Realm (10.45.2)

DEPENDENCIES:
  - Realm

SPEC REPOS:
  "https://cdn.cocoapods.org/":
    - Realm

COCOAPODS: 1.13.0
"""

NOT_A_LOCKFILE = "name: my-project\nversion: 1.0.0\n"
EMPTY = "   \n"
MALFORMED_YAML = "PODS:\n  - [unclosed\n"
