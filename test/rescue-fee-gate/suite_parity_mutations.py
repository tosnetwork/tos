"""EXPERIMENT: the C++/Rust PQCHECKSIG_SUITE parity check must be able to fail.

For each mutation of the Rust VM: apply it, rebuild the Rust driver, run the scenarios, and
require a difference from the C++ output. The source is always restored.

Usage: suite_parity_mutations.py <scenarios.tsv> <cpp-output> <cargo-target-dir>
"""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CARGO = ROOT / "tosctl/src"
PQ = CARGO / "vm/src/executor/pq.rs"
LMS = CARGO / "vm/src/executor/lms_fee.rs"

MUTATIONS = {
    "LMS tariff 3 -> 4 gas per compression": (PQ, "const LMS_GAS_PER_COMPRESSION: i64 = 3;", "const LMS_GAS_PER_COMPRESSION: i64 = 4;"),
    "LMS path: sibling order swapped": (
        LMS,
        "        tmp = if node & 1 == 1 {",
        "        tmp = if node & 1 == 0 {",
    ),
    "Falcon suite accepts a non-empty context": (PQ, "            read_bytes(engine, context, 0)?;", "            read_bytes(engine, context, 1)?;"),
    "suite enabled only from version 19": (PQ, "const SUITE_MIN_VERSION: u32 = 18;", "const SUITE_MIN_VERSION: u32 = 19;"),
    "Falcon opened at genesis through the generic opcode": (
        PQ,
        "const FALCON512_MIN_VERSION: u32 = 19;",
        "const FALCON512_MIN_VERSION: u32 = 18;",
    ),
    "SLH base gas 750,000 -> 749,999": (
        PQ,
        "const SLH_BASE_GAS: i64 = 750_000;",
        "const SLH_BASE_GAS: i64 = 749_999;",
    ),
}


def rust_output(scenarios, target):
    env = dict(os.environ, CARGO_TARGET_DIR=str(target))
    subprocess.run(["cargo", "build", "-q", "-p", "tos_vm", "--example", "suite-parity"], cwd=CARGO,
                   env=env, check=True, capture_output=True)
    return subprocess.run([str(Path(target) / "debug/examples/suite-parity"), str(scenarios)],
                          check=True, capture_output=True, text=True).stdout


def main(scenarios, cpp_output, target):
    cpp = Path(cpp_output).read_text()
    if rust_output(scenarios, target) != cpp:
        sys.exit("baseline differs: fix parity before measuring sensitivity")
    print("baseline: identical")
    failed = False
    for name, (path, old, new) in MUTATIONS.items():
        text = path.read_text()
        if text.count(old) != 1:
            sys.exit(f"{name}: anchor not found exactly once")
        path.write_text(text.replace(old, new))
        try:
            out = rust_output(scenarios, target)
        finally:
            path.write_text(text)
        differ = sum(a != b for a, b in zip(out.splitlines(), cpp.splitlines()))
        print(f"{name}: {'caught' if differ else 'ESCAPED'} ({differ} rows differ)")
        failed |= not differ
    rust_output(scenarios, target)  # leave the driver built from the restored source
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main(*sys.argv[1:4])
