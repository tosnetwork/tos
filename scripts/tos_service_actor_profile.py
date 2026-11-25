#!/usr/bin/env python3
"""Service Actor build profiles: each rail's release build and its test-only build.

Two rails exist: the native rail (crypto/smartcont/service-actor-code.fc) and
the token rail (crypto/smartcont/service-actor-token-code.fc). Each has a
release profile, which compiles its source as it is, and a test profile, which
compiles a derived copy in which only the constants listed in TEST_OVERRIDES
take other values; every other byte of the source and of the files it includes
is unchanged. The test profiles exist so that test networks can exercise the
timeout-refund path in minutes instead of hours. A test code hash differs from
its release code hash, so nothing that pins a release hash accepts a
test-profile actor.

Usage:
    tos_service_actor_profile.py manifest <profile>
    tos_service_actor_profile.py source <profile> <work-directory>

Standard library only.
"""

from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SOURCE = "crypto/smartcont/service-actor-code.fc"
TOKEN_SOURCE = "crypto/smartcont/service-actor-token-code.fc"
RELEASE = "release"
TEST = "test"
TOKEN = "token"
TOKEN_TEST = "token-test"

# The only constants the test profile may change, and their test values. Each
# replaces a lower bound with a smaller one; no upper bound, fee or capacity
# constant is ever overridden.
TEST_OVERRIDES = {"MIN_RESPONSE_SLA": 600, "MIN_REFUND_CLAIM_WINDOW": 600}

NATIVE_SDK = "tosctl/src/node-control/contracts/src/service_actor.rs"
TOKEN_SDK = "tosctl/src/node-control/contracts/src/service_actor_token.rs"

# "release" names the profile a test profile is the test build of; a release
# profile names none.
PROFILES = {
    RELEASE: {
        "contract": "tos-service-actor-v1",
        "source": SOURCE,
        "sdk": NATIVE_SDK,
        "manifest": "crypto/smartcont/tos-service-actor-v1.release.json",
        "artifact_base64": "crypto/smartcont/tos-service-actor-v1.boc.base64",
        "sdk_constant": "SERVICE_ACTOR_CODE_B64",
        "default_output": "crypto/smartcont/artifacts/tos-service-actor-v1.boc",
        "overrides": {},
        "release": None,
    },
    TEST: {
        "contract": "tos-service-actor-v1",
        "source": SOURCE,
        "sdk": NATIVE_SDK,
        "manifest": "crypto/smartcont/tos-service-actor-v1-test.release.json",
        "artifact_base64": "crypto/smartcont/tos-service-actor-v1-test.boc.base64",
        "sdk_constant": "SERVICE_ACTOR_TEST_PROFILE_CODE_B64",
        "default_output": "crypto/smartcont/artifacts/tos-service-actor-v1-test.boc",
        "overrides": TEST_OVERRIDES,
        "release": RELEASE,
    },
    TOKEN: {
        "contract": "tos-service-actor-token-v1",
        "source": TOKEN_SOURCE,
        "sdk": TOKEN_SDK,
        "manifest": "crypto/smartcont/tos-service-actor-token-v1.release.json",
        "artifact_base64": "crypto/smartcont/tos-service-actor-token-v1.boc.base64",
        "sdk_constant": "SERVICE_ACTOR_TOKEN_CODE_B64",
        "default_output": "crypto/smartcont/artifacts/tos-service-actor-token-v1.boc",
        "overrides": {},
        "release": None,
    },
    TOKEN_TEST: {
        "contract": "tos-service-actor-token-v1",
        "source": TOKEN_SOURCE,
        "sdk": TOKEN_SDK,
        "manifest": "crypto/smartcont/tos-service-actor-token-v1-test.release.json",
        "artifact_base64": "crypto/smartcont/tos-service-actor-token-v1-test.boc.base64",
        "sdk_constant": "SERVICE_ACTOR_TOKEN_TEST_PROFILE_CODE_B64",
        "default_output": "crypto/smartcont/artifacts/tos-service-actor-token-v1-test.boc",
        "overrides": TEST_OVERRIDES,
        "release": TOKEN,
    },
}

# Each test profile and the release profile it derives from.
TEST_PAIRS = tuple((selected["release"], name) for name, selected in PROFILES.items()
                   if selected["release"] is not None)

INCLUDE = re.compile(r'^\s*#include\s+"([^"]+)"\s*;', re.MULTILINE)


class ProfileError(RuntimeError):
    pass


def profile(name: str) -> dict:
    if name not in PROFILES:
        raise ProfileError(
            f"unknown Service Actor profile {name!r} (expected one of {sorted(PROFILES)})"
        )
    return PROFILES[name]


def include_closure(source: Path) -> list[Path]:
    """The source and every file it transitively includes, as resolved paths."""
    seen: list[Path] = []
    pending = [source.resolve()]
    while pending:
        path = pending.pop()
        if path in seen:
            continue
        if not path.is_file():
            raise ProfileError(f"included file is missing: {path}")
        seen.append(path)
        for name in INCLUDE.findall(path.read_text()):
            pending.append((path.parent / name).resolve())
    return seen


def apply_overrides(text: str, overrides: dict[str, int]) -> str:
    """Replace the value of each named top-level `const int` declaration.

    Each name must be declared exactly once, at the start of a line, with a
    decimal value; anything else is refused rather than guessed at.
    """
    for name, value in overrides.items():
        if type(value) is not int or value <= 0:
            raise ProfileError(f"override {name} must be a positive integer")
        pattern = re.compile(rf"^(const int {re.escape(name)} = )([0-9]+)(;)", re.MULTILINE)
        matches = pattern.findall(text)
        if len(matches) != 1:
            raise ProfileError(
                f"constant {name} is declared {len(matches)} times; expected exactly once"
            )
        if int(matches[0][1]) <= value:
            raise ProfileError(
                f"override {name}={value} does not lower the source value {matches[0][1]}"
            )
        text = pattern.sub(lambda match: f"{match.group(1)}{value}{match.group(3)}", text, count=1)
    return text


def source_for(name: str, work: Path, root: Path = REPO) -> Path:
    """The main source file to compile for this profile.

    The release profile returns the checked-in source. The test profile copies
    the source's include closure under work (keeping paths relative to root,
    so every #include resolves as it does in the checkout) and rewrites only
    the overridden constants in the copied main file.
    """
    selected = profile(name)
    overrides = selected["overrides"]
    original = (root / selected["source"]).resolve()
    if not overrides:
        return original
    root = root.resolve()
    for path in include_closure(original):
        target = work / path.relative_to(root)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    derived = work / selected["source"]
    derived.write_text(apply_overrides(original.read_text(), overrides))
    return derived


def main() -> int:
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "manifest":
            print(REPO / profile(sys.argv[2])["manifest"])
            return 0
        if len(sys.argv) == 3 and sys.argv[1] == "default-output":
            print(REPO / profile(sys.argv[2])["default_output"])
            return 0
        if len(sys.argv) == 4 and sys.argv[1] == "source":
            print(source_for(sys.argv[2], Path(sys.argv[3])))
            return 0
    except ProfileError as error:
        print(f"Service Actor profile error: {error}", file=sys.stderr)
        return 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
