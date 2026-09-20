"""Verify the 3.9 fallback TOML reader actually works.

Run standalone: python3 verify_fallback.py
"""
import pathlib
import re

src = pathlib.Path("tests/test_release_pins.py").read_text()
# Force the ModuleNotFoundError branch regardless of the running interpreter
forced = src.replace("    import tomllib  # type: ignore[import-not-found]",
                     "    raise ModuleNotFoundError('forced')")
assert forced != src, "could not force the fallback branch"

ns = {"__file__": str(pathlib.Path("tests/test_release_pins.py").resolve())}
exec(compile(forced, "test_release_pins.py", "exec"), ns)

version = ns["shipping_version"]()
print(f"  fallback reader returned version: {version}")

# It must match what tomllib-equivalent parsing gives
real = re.search(r'^version = "([^"]+)"', pathlib.Path("pyproject.toml").read_text(), re.M)
assert real, "pyproject has no version line"
assert version == real.group(1), f"fallback {version} != actual {real.group(1)}"
print(f"  matches pyproject.toml exactly: {real.group(1)}")

# And the pin test must still pass using it
ns["test_every_advertised_pin_matches_the_shipping_version"]()
print("  pin test passes via the fallback path")
