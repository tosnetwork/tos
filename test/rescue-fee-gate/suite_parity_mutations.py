"""EXPERIMENT: the C++/Rust PQCHECKSIG_SUITE parity check must be able to fail.

For each mutation of the Rust VM: apply its edits, rebuild the Rust driver, run the scenarios,
and require every row the mutation names to differ from the C++ output; a difference somewhere
else does not show that the named boundary is tested. A mutation may also name Rust unit tests
that must fail, for behaviour no scenario can observe. The source is always restored.

Usage: suite_parity_mutations.py <scenarios.tsv> <cpp-output> <cargo-target-dir> [--list]
--list prints the rows each mutation changes instead of checking them.
"""

import os
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[2]
CARGO = ROOT / "tosctl/src"
PQ = CARGO / "vm/src/executor/pq.rs"
LMS = CARGO / "vm/src/executor/lms_fee.rs"
CORE = CARGO / "vm/src/executor/engine/core.rs"


class Mutation(NamedTuple):
    path: Path
    edits: list  # (old, new) pairs, each old text present exactly once
    rows: tuple  # scenario ids that must differ
    tests: tuple = ()  # Rust unit tests that must fail, for what no scenario can observe


MUTATIONS = {
    "LMS tariff 3 -> 4 gas per compression": Mutation(
        PQ,
        [("const LMS_GAS_PER_COMPRESSION: i64 = 3;", "const LMS_GAS_PER_COMPRESSION: i64 = 4;")],
        ("s4-h20w4-valid", "s4-out-of-gas-before-signature"),
    ),
    "LMS path: sibling order swapped": Mutation(
        LMS,
        [("        tmp = if node & 1 == 1 {", "        tmp = if node & 1 == 0 {")],
        ("s4-h20w4-valid", "s4-h20w4-random-key"),
    ),
    "Falcon suite accepts a non-empty context": Mutation(
        PQ,
        [
            (
                "            read_bytes_priced(engine, context, 0, FALCON512_BYTE_GAS)?;",
                "            read_bytes_priced(engine, context, 1, FALCON512_BYTE_GAS)?;",
            )
        ],
        ("s2-nonempty-context",),
    ),
    "suite enabled before version 16": Mutation(
        PQ,
        [("const SUITE_MIN_VERSION: u32 = 16;", "const SUITE_MIN_VERSION: u32 = 15;")],
        ("s2-refused-before-genesis", "version-15"),
    ),
    "suite enabled only from version 17": Mutation(
        PQ,
        [("const SUITE_MIN_VERSION: u32 = 16;", "const SUITE_MIN_VERSION: u32 = 17;")],
        ("s1-valid", "s2-valid", "s3-valid", "s4-h20w4-valid"),
    ),
    "Falcon generic gate differs from the dedicated gate": Mutation(
        PQ,
        [("const FALCON512_MIN_VERSION: u32 = 16;", "const FALCON512_MIN_VERSION: u32 = 17;")],
        ("s2-valid",),
    ),
    "SLH base gas 750,000 -> 749,999": Mutation(
        PQ,
        [("const SLH_BASE_GAS: i64 = 750_000;", "const SLH_BASE_GAS: i64 = 749_999;")],
        ("s3-valid", "s3-out-of-gas-base"),
    ),
    "instruction step not counted on fetch": Mutation(
        CORE,
        [
            (
                "            self.step += 1;\n            let execution_result = match HANDLERS_CP0.get_handler(self) {\n",
                "            let execution_result = match HANDLERS_CP0.get_handler(self) {\n",
            )
        ],
        ("s1-valid", "steps-unassigned-opcode", "steps-truncated-prefix-ff"),
    ),
    "instruction step counted again on decode": Mutation(
        CORE,
        [
            (
                "        self.cmd.vars.clear();\n        self.extract_instruction()\n",
                "        self.cmd.vars.clear();\n        self.step += 1;\n        self.extract_instruction()\n",
            )
        ],
        ("s1-valid", "s3-valid"),
    ),
    "child out of gas exits with 13, not -14": Mutation(
        CORE,
        [
            (
                "            return !(ExceptionCode::OutOfGas as i32);\n",
                "            return ExceptionCode::OutOfGas as i32;\n",
            )
        ],
        ("child-oog-instruction-exit", "child-oog-c2-switch-exit", "child-oog-exit-isolated"),
    ),
    "child out of gas keeps its stack under the gas": Mutation(
        CORE,
        [
            (
                "OutOfGas) {\n            self.cc.stack = Stack::new();\n",
                "OutOfGas) {\n",
            )
        ],
        (),
        ("child_out_of_gas_leaves_only_the_gas_consumed",),
    ),
    "child out of gas returns 0, not the gas it consumed": Mutation(
        CORE,
        [
            (
                "            self.cc.stack.push_int(self.gas_used());\n",
                "            self.cc.stack.push_int(0);\n",
            )
        ],
        ("child-oog-instruction-value", "child-oog-c2-switch-value"),
        ("child_out_of_gas_leaves_only_the_gas_consumed",),
    ),
    "+8 returns the gas used capped at the limit": Mutation(
        CORE,
        [
            (
                "            self.cc.stack.push_int(child_gas_used);\n",
                "            self.cc.stack.push_int(child.gas.get_gas_used());\n",
            )
        ],
        ("child-oog-gas", "child-oog-gas-isolated"),
    ),
    "parent pays the child's limit, not one more": Mutation(
        CORE,
        [
            (
                "child_gas_used.min(child.gas.get_gas_limit() + 1)",
                "child_gas_used.min(child.gas.get_gas_limit())",
            )
        ],
        ("child-oog-instruction-exit", "child-oog-nested-restore-value"),
    ),
    "no step for running out of gas in the exception handler switch": Mutation(
        CORE,
        [
            (
                "OutOfGas) {\n                self.step += 1;\n",
                "OutOfGas) {\n",
            )
        ],
        ("child-oog-c2-switch-exit", "child-oog-c2-switch-value"),
    ),
}


def rust_output(scenarios, target):
    env = dict(os.environ, CARGO_TARGET_DIR=str(target))
    subprocess.run(
        ["cargo", "build", "--locked", "-q", "-p", "tos_vm", "--example", "suite-parity"],
        cwd=CARGO,
        env=env,
        check=True,
        capture_output=True,
    )
    return subprocess.run(
        [str(Path(target) / "debug/examples/suite-parity"), str(scenarios)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def unit_test_fails(name, target):
    env = dict(os.environ, CARGO_TARGET_DIR=str(target))
    run = subprocess.run(
        ["cargo", "test", "--locked", "-q", "-p", "tos_vm", "--lib", name],
        cwd=CARGO,
        env=env,
        capture_output=True,
        text=True,
    )
    # A build failure is not a failing test: require the test itself to have run and failed.
    return "test result: FAILED. 0 passed; 1 failed" in run.stdout


def main(scenarios, cpp_output, target, *flags):
    # Cargo runs in tosctl/src, so a relative target would build somewhere the driver is not
    # read from, and every mutation would run the unmutated driver.
    target = Path(target).resolve()
    listing = flags == ("--list",)
    cpp = Path(cpp_output).read_text()
    if rust_output(scenarios, target) != cpp:
        sys.exit("baseline differs: fix parity before measuring sensitivity")
    print("baseline: identical")
    ids = [line.split("\t")[0] for line in cpp.splitlines()]
    failed = False
    for name, m in MUTATIONS.items():
        missing = [r for r in m.rows if r not in ids]
        if missing and not listing:
            sys.exit(f"{name}: named rows not in the scenarios: {missing}")
        text = mutated = m.path.read_text()
        for old, new in m.edits:
            if mutated.count(old) != 1:
                sys.exit(f"{name}: anchor not found exactly once")
            mutated = mutated.replace(old, new)
        m.path.write_text(mutated)
        try:
            out = rust_output(scenarios, target)
            failing = [t for t in m.tests if unit_test_fails(t, target)]
        finally:
            m.path.write_text(text)
        if len(out.splitlines()) != len(cpp.splitlines()):
            sys.exit(f"{name}: incomplete output is not mutation evidence")
        differ = {i for i, a, b in zip(ids, out.splitlines(), cpp.splitlines()) if a != b}
        if listing:
            print(f"{name}: {sorted(differ)}, failing tests {failing}")
            continue
        escaped = [r for r in m.rows if r not in differ]
        passing = [t for t in m.tests if t not in failing]
        ok = bool(m.rows or m.tests) and not escaped and not passing
        print(f"{name}: {'caught' if ok else 'ESCAPED'} ({len(differ)} rows differ)")
        if escaped:
            print(f"  named rows unchanged: {escaped}")
        if passing:
            print(f"  named tests still pass: {passing}")
        failed |= not ok
    if rust_output(scenarios, target) != cpp:
        sys.exit("restored baseline differs")
    print("restored baseline: identical")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main(*sys.argv[1:])
