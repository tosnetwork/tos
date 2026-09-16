"""Require that nothing a validator ships can assemble an owner approval.

An owner approval states a fact that already happened outside this boundary: the
owner's own account executed a finalized transaction carrying it. A validator
verifies that fact. Code able to manufacture one belongs only to the drivers that
extract fixtures from real executions.

Two independent checks, because each misses what the other catches. The source
scan sees a caller that has been written but not yet built. The symbol check asks
the linker what a production library actually contains, which no amount of text
can argue with.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PRODUCER = "make_owner_execution_proof"
MACRO = "TOS_VALIDATOR_AUTH_TEST_PRODUCER"

# The module that defines it, and the drivers that extract fixtures.
ALLOWED_SOURCES = {"validator/auth/owner-proof.h", "validator/auth/owner-proof.cpp"}
ALLOWED_PREFIXES = ("test/",)
# Where the macro may be named at all: the module it guards and the build file
# that turns it on for those drivers.
ALLOWED_MACRO = ALLOWED_SOURCES | {"test/validator-auth-implementation/CMakeLists.txt"}


def tracked_files() -> list[str]:
    # Untracked files count. A caller added to a new production file and not yet
    # committed is still a caller, and a scan that only sees the index would
    # report a clean boundary while one sat on disk.
    listing = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"],
                             cwd=ROOT, capture_output=True, text=True, check=True)
    return sorted(set(listing.stdout.splitlines()))


def offenders(contents: dict[str, str], needle: str, allowed: set[str]) -> list[str]:
    return sorted(path for path, text in contents.items()
                  if needle in text and path not in allowed and not path.startswith(ALLOWED_PREFIXES))


def read_all(paths: list[str]) -> dict[str, str]:
    contents: dict[str, str] = {}
    for path in paths:
        full = ROOT / path
        if not full.is_file():
            continue
        try:
            contents[path] = full.read_text()
        except (UnicodeDecodeError, OSError):
            continue
    return contents


def symbols(binary: Path) -> str:
    listing = subprocess.run(["nm", "-C", str(binary)], capture_output=True, text=True, check=False)
    return listing.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=ROOT / "build-p0")
    arguments = parser.parse_args()

    paths = tracked_files()
    if not paths:
        print("BOUNDARY-NO-FILES-LISTED", file=sys.stderr)
        return 1
    contents = read_all(paths)

    # The scan proves nothing until it is shown to find something, so a file that
    # must be rejected is added to the same inputs the real check reads.
    planted = dict(contents)
    planted["validator/impl/invented-caller.cpp"] = f"auto proof = {PRODUCER}(state, block);\n"
    if not offenders(planted, PRODUCER, ALLOWED_SOURCES):
        print("BOUNDARY-SCAN-CANNOT-SEE-A-CALLER", file=sys.stderr)
        return 1

    found = offenders(contents, PRODUCER, ALLOWED_SOURCES)
    if found:
        print(f"PRODUCER-REACHABLE-FROM {' '.join(found)}", file=sys.stderr)
        return 1
    macro = offenders(contents, MACRO, ALLOWED_MACRO)
    if macro:
        print(f"PRODUCER-MACRO-NAMED-IN {' '.join(macro)}", file=sys.stderr)
        return 1

    # The verifier must still be here. A boundary that removed both would pass
    # every check above while deleting the thing being protected.
    verifier = [path for path, text in contents.items() if "verify_owner_execution" in text]
    if not verifier:
        print("VERIFIER-ABSENT", file=sys.stderr)
        return 1

    library = next(iter((arguments.build / "validator/auth").glob("libtos_validator_auth_native.a")), None)
    driver = arguments.build / "test/validator-auth-implementation/test-p0-owner-proof"
    if library is None or not driver.is_file():
        print("BOUNDARY-BINARIES-MISSING", file=sys.stderr)
        return 1
    shipped, extracting = symbols(library), symbols(driver)
    if not re.search(PRODUCER, extracting):
        print("FIXTURE-DRIVER-CANNOT-PRODUCE", file=sys.stderr)
        return 1
    if re.search(PRODUCER, shipped):
        print("PRODUCER-LINKED-INTO-THE-LIBRARY", file=sys.stderr)
        return 1
    if not re.search("verify_owner_execution", shipped):
        print("VERIFIER-NOT-LINKED", file=sys.stderr)
        return 1

    print("PASS: a validator build verifies owner approvals and contains nothing that can assemble one")
    return 0


if __name__ == "__main__":
    sys.exit(main())
