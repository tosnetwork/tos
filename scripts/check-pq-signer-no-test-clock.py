#!/usr/bin/env python3
"""The production consensus signer has no way to move the key deadline's clock.

The key store's hard deadline is read from the wall clock. Tests replace that clock
through `ValidatorPQKeyStore::set_clock_for_test`, which exists only in the separate
`tos_pq_consensus_signer_test_clock` library, compiled with TOS_PQ_SIGNER_TEST_CLOCK. This
checks, and fails on any check it cannot carry out:

  - symbols: no production archive or binary defines the seam; the test archive does
    (so a silent `nm` cannot pass), and the production archive does define the signer;
  - headers: code compiled against the production header cannot call the seam; the same
    code compiles with the test definition (so a broken compile cannot pass);
  - build wiring: only the test library is given TOS_PQ_SIGNER_TEST_CLOCK, and only the
    test that needs the clock links it.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SEAM = "set_clock_for_test"
SIGNER = "ValidatorPQKeyStore::sign_consensus"
TEST_LIBRARY = "tos_pq_consensus_signer_test_clock"
TEST_DEFINE = "TOS_PQ_SIGNER_TEST_CLOCK"
# The only places the test library and its definition may be named.
ALLOWED = {
    "crypto/pq/CMakeLists.txt": {TEST_LIBRARY, TEST_DEFINE},
    "CMakeLists.txt": {TEST_LIBRARY},
}
ALLOWED_LINKERS = {
    "test-pq-consensus-key-rotation",
    TEST_LIBRARY,
}  # the library declaring its own links

CALLER = """#include "consensus-pq-signer.h"
static std::int64_t fixed() noexcept { return 0; }
void call() { tos::pq::ValidatorPQKeyStore::set_clock_for_test(&fixed); }
"""


class Failure(Exception):
    pass


def defined_symbols(nm: str, path: Path) -> list[str]:
    if not path.is_file():
        raise Failure(f"{path} does not exist")
    result = subprocess.run(
        [nm, "--defined-only", "-C", str(path)], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise Failure(f"{nm} failed on {path}: {result.stderr.strip()}")
    if not result.stdout.strip():
        raise Failure(f"{nm} listed no symbols in {path}")
    return result.stdout.splitlines()


def check_symbols(nm: str, production: list[Path], test_clock: Path) -> None:
    for path in production:
        symbols = defined_symbols(nm, path)
        found = [line for line in symbols if SEAM in line]
        if found:
            raise Failure(f"{path} defines the clock seam: {found[:2]}")
    library_symbols = defined_symbols(nm, production[0])
    if not any(SIGNER in line for line in library_symbols):
        raise Failure(f"{production[0]} does not define {SIGNER}; it is not the signer library")
    if not any(SEAM in line for line in defined_symbols(nm, test_clock)):
        raise Failure(f"{test_clock} defines no clock seam; this check would see nothing")


def check_header(cxx: str, include_dir: Path) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / "caller.cpp"
        source.write_text(CALLER)
        base = [cxx, "-std=c++20", "-fsyntax-only", f"-I{include_dir}", str(source)]
        production = subprocess.run(base, capture_output=True, text=True, check=False)
        if production.returncode == 0:
            raise Failure("code compiled against the production header can call the clock seam")
        if SEAM not in production.stderr:
            raise Failure(
                f"the production-header compile failed for another reason: {production.stderr[-400:]}"
            )
        test = subprocess.run(
            base + [f"-D{TEST_DEFINE}=1"], capture_output=True, text=True, check=False
        )
        if test.returncode != 0:
            raise Failure(
                f"the caller does not compile with the test definition: {test.stderr[-400:]}"
            )


def check_wiring(source_root: Path) -> None:
    seen_definition = False
    for path in sorted(source_root.rglob("CMakeLists.txt")):
        relative = path.relative_to(source_root).as_posix()
        if relative.startswith(("build", "third-party", ".")) or "/build" in relative:
            continue
        text = path.read_text(errors="replace")
        for name in (TEST_LIBRARY, TEST_DEFINE):
            if name in text and name not in ALLOWED.get(relative, set()):
                raise Failure(f"{relative} names {name}")
        if relative == "crypto/pq/CMakeLists.txt":
            seen_definition = TEST_DEFINE in text
            # The definition is given to the test library and to nothing else.
            for match in re.finditer(r"target_compile_definitions\((\S+)[^)]*\)", text, re.S):
                if TEST_DEFINE in match.group(0) and match.group(1) != TEST_LIBRARY:
                    raise Failure(f"{match.group(1)} is compiled with {TEST_DEFINE}")
        for match in re.finditer(r"target_link_libraries\((\S+)[^)]*\)", text, re.S):
            if TEST_LIBRARY in match.group(0) and match.group(1) not in ALLOWED_LINKERS:
                raise Failure(f"{match.group(1)} links {TEST_LIBRARY}")
    if not seen_definition:
        raise Failure(
            f"crypto/pq/CMakeLists.txt does not define {TEST_DEFINE} for the test library"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nm", required=True)
    parser.add_argument("--cxx", required=True)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument(
        "--production", required=True, type=Path, help="the production signer archive"
    )
    parser.add_argument(
        "--binary", action="append", type=Path, default=[], help="a production binary to inspect"
    )
    parser.add_argument(
        "--test-clock", required=True, type=Path, help="the test-clock signer archive"
    )
    args = parser.parse_args()
    try:
        if shutil.which(args.nm) is None and not os.access(args.nm, os.X_OK):
            raise Failure(f"no nm at {args.nm}")
        if shutil.which(args.cxx) is None and not os.access(args.cxx, os.X_OK):
            raise Failure(f"no compiler at {args.cxx}")
        check_symbols(args.nm, [args.production, *args.binary], args.test_clock)
        check_header(args.cxx, args.source_root / "crypto/pq")
        check_wiring(args.source_root)
    except Failure as failure:
        print(f"PQ_SIGNER_TEST_CLOCK_FAILED {failure}")
        return 1
    print(
        "PQ_SIGNER_TEST_CLOCK_OK no production archive or binary defines the clock seam, the production header "
        "cannot call it, and only the rotation test links the test-clock signer"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
