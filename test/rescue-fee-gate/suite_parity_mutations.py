"""EXPERIMENT: the C++/Rust PQCHECKSIG_SUITE parity check must be able to fail.

For each mutation of the Rust VM: apply its edits, rebuild the Rust driver, run the scenarios,
and require every row the mutation names to differ from the C++ output; a difference somewhere
else does not show that the named boundary is tested. A mutation may also name Rust unit tests
that must fail, for behaviour no scenario can observe, and rows of the end-state scenarios
(vm_endstate_scenarios.py) that vm_endstate_compare.py must then report as different from the
C++ end state. The source is always restored.

Usage: suite_parity_mutations.py <scenarios.tsv> <cpp-output> <cargo-target-dir>
           <endstate-scenarios.tsv> <endstate-cpp-output> [--list]
--list prints the rows each mutation changes instead of checking them.
"""

import os
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vm_endstate_compare import differences  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
CARGO = ROOT / "tosctl/src"
PQ = CARGO / "vm/src/executor/pq.rs"
LMS = CARGO / "vm/src/executor/lms_fee.rs"
CORE = CARGO / "vm/src/executor/engine/core.rs"
CONTINUATION = CARGO / "vm/src/executor/continuation.rs"
ERROR = CARGO / "vm/src/error.rs"
HANDLERS = CARGO / "vm/src/executor/engine/handlers.rs"
GAS = CARGO / "vm/src/executor/gas/mod.rs"
CHILD_STACK_TEST = (
    "executor::engine::core::nesting_depth_tests::child_out_of_gas_leaves_only_the_gas_consumed"
)


class Mutation(NamedTuple):
    path: Path
    edits: list  # (old, new) pairs, each old text present exactly once
    rows: tuple  # scenario ids that must differ
    tests: tuple = ()  # Rust unit tests that must fail, for what no scenario can observe
    endstate: tuple = ()  # end-state scenario ids that must differ from the C++ end state


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
    "SLH base gas 4,500 -> 4,499": Mutation(
        PQ,
        [("const SLH_BASE_GAS: i64 = 4_500;", "const SLH_BASE_GAS: i64 = 4_499;")],
        ("s3-valid", "s3-out-of-gas-base-last", "p-child-oog-base-value"),
    ),
    "SLH byte gas 0 -> 1": Mutation(
        PQ,
        [("const SLH_BYTE_GAS: i64 = 0;", "const SLH_BYTE_GAS: i64 = 1;")],
        ("s3-valid", "p-child-oog-load-value"),
    ),
    "SLH attempts per execution 1 -> 2": Mutation(
        PQ,
        [("const SLH_MAX_PER_EXECUTION: u32 = 1;", "const SLH_MAX_PER_EXECUTION: u32 = 2;")],
        ("p-two-calls", "p-child-then-parent", "p-restore-oog-then-parent"),
    ),
    "SLH attempt not counted": Mutation(
        PQ,
        [("            engine.slh_counter = engine.slh_counter.saturating_add(1);\n", "")],
        ("p-two-calls", "p-child-oog-base-then-parent"),
    ),
    "SLH attempt taken after the base charge": Mutation(
        PQ,
        [
            (
                "            engine.slh_counter = engine.slh_counter.saturating_add(1);\n"
                "            engine.try_use_gas(SLH_BASE_GAS)?;\n",
                "            engine.try_use_gas(SLH_BASE_GAS)?;\n"
                "            engine.slh_counter = engine.slh_counter.saturating_add(1);\n",
            )
        ],
        ("p-child-oog-base-then-parent",),
    ),
    "SLH attempt taken after the operands load": Mutation(
        PQ,
        [
            ("            engine.slh_counter = engine.slh_counter.saturating_add(1);\n", ""),
            (
                "            let message = read_bytes_priced(engine, message, MAX_MESSAGE_BYTES, "
                "SLH_BYTE_GAS)?;\n",
                "            let message = read_bytes_priced(engine, message, MAX_MESSAGE_BYTES, "
                "SLH_BYTE_GAS)?;\n"
                "            engine.slh_counter = engine.slh_counter.saturating_add(1);\n",
            ),
        ],
        ("p-child-oog-load-then-parent", "p-try-malformed-then-retry"),
    ),
    "SLH count reset on child entry": Mutation(
        CORE,
        [("            slh_counter: self.slh_counter,", "            slh_counter: 0,")],
        ("p-parent-then-child", "p-parent-empty-child-then-parent"),
    ),
    "SLH count not written back from the child": Mutation(
        CORE,
        [("        self.slh_counter = child.slh_counter;\n", "")],
        ("p-child-then-parent", "p-child-isolated-then-parent", "p-restore-oog-then-parent"),
    ),
    "SLH count reset by isolate_gas": Mutation(
        CORE,
        [
            (
                "            self.checked_signatures_count = 0;\n",
                "            self.checked_signatures_count = 0;\n            self.slh_counter = 0;\n",
            )
        ],
        ("p-parent-then-child-isolated", "p-parent-empty-child-isolated-then-parent"),
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
        ERROR,
        [
            (
                "        Some(ExceptionCode::OutOfGas) => !(ExceptionCode::OutOfGas as i32),\n",
                "        Some(ExceptionCode::OutOfGas) => ExceptionCode::OutOfGas as i32,\n",
            )
        ],
        ("child-oog-instruction-exit", "child-oog-c2-switch-exit", "child-oog-exit-isolated"),
    ),
    "out of gas keeps the stack under the gas": Mutation(
        CORE,
        [
            (
                "            let gas_used = self.gas_used();\n            self.cc.stack = Stack::new();\n",
                "            let gas_used = self.gas_used();\n",
            )
        ],
        (),
        (CHILD_STACK_TEST,),
        ("end-out-of-gas", "setgaslimit-0"),
    ),
    "child out of gas returns 0, not the gas it consumed": Mutation(
        CORE,
        [
            (
                "            self.cc.stack.push_int(gas_used);\n",
                "            self.cc.stack.push_int(0);\n",
            )
        ],
        ("child-oog-instruction-value", "child-oog-c2-switch-value"),
        (CHILD_STACK_TEST,),
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
    "uncommitted child returns empty cells, not null": Mutation(
        CORE,
        [
            (
                "            None if self.block_version >= 11 => {\n",
                "            None if false => {\n",
            )
        ],
        ("child-oog-uncommitted-data", "child-error-uncommitted-actions"),
    ),
    "child out of gas commits its live data": Mutation(
        CORE,
        [
            (
                "            let gas_used = self.gas_used();\n            self.cc.stack = Stack::new();\n",
                "            let gas_used = self.gas_used();\n            self.try_commit().ok();\n"
                "            self.cc.stack = Stack::new();\n",
            )
        ],
        ("child-oog-committed-data", "child-oog-uncommitted-actions"),
    ),
    "default exception handler reports exit code 13 as out of gas": Mutation(
        CORE,
        [
            (
                "        fail!(Exception::from_number(number, String::new(), file!(), line!()))\n",
                "        fail!(match ExceptionCode::from_i32(number) {\n"
                "            Some(code) => Exception::from_code(code, String::new(), file!(), line!()),\n"
                "            None => Exception::from_number(number, String::new(), file!(), line!()),\n"
                "        })\n",
            )
        ],
        (
            "child-exits-13-via-c2-exit",
            "child-forwards-throw-13-to-saved-c2-exit",
            "exits-13-via-c2",
        ),
    ),
    "default exception handler leaves its exit code on the returned stack": Mutation(
        CORE,
        [
            (
                "        fail!(Exception::from_number(number, String::new(), file!(), line!()))\n",
                "        self.cc.stack.push_int(number);\n"
                "        fail!(Exception::from_number(number, String::new(), file!(), line!()))\n",
            )
        ],
        ("child-exits-13-via-c2-value", "child-exits-null-via-c2-value"),
        (),
        ("excquit-13-keeps-below", "excquit-13-alone"),
    ),
    "default exception handler leaves the exit code of a raised exception": Mutation(
        CORE,
        [
            (
                "                    self.cc.stack.push(value);\n                    fail!(exception)\n",
                "                    self.cc.stack.push(value);\n"
                "                    self.cc.stack.push(int!(exception.exception_or_custom_code()));\n"
                "                    fail!(exception)\n",
            )
        ],
        (),
        (),
        ("end-throw-6", "end-throwarg-5-42", "end-unassigned-opcode"),
    ),
    "error argument is not the final top of the stack": Mutation(
        CORE,
        [
            (
                "        let top = self.cc.stack.get(0).cloned().unwrap_or_default();\n",
                "        let top = StackItem::None;\n",
            )
        ],
        (),
        (),
        ("end-throw-6", "excquit-13-keeps-below", "handler-nargs-3-vm-error"),
    ),
    "exception handler always takes two arguments": Mutation(
        CORE,
        [
            (
                "        self.cmd.push_var(c2.clone());\n",
                "        self.cmd.push_var(c2.clone());\n"
                "        self.cmd.vars[n].as_continuation_mut()?.nargs = 2;\n",
            )
        ],
        (),
        (),
        ("handler-nargs-3-vm-error", "handler-nargs-3-throw-6"),
    ),
    "explicit THROW is not dispatched again when the handler cannot be entered": Mutation(
        CORE,
        [("                if retry {\n", "                if false {\n")],
        (),
        (),
        ("handler-nargs-3-throw-6",),
    ),
    "implicit PUSHINT counted as a step": Mutation(
        CORE,
        [
            (
                "    fn step_pushint(&mut self, code: i32) -> Result<Option<i32>> {\n",
                "    fn step_pushint(&mut self, code: i32) -> Result<Option<i32>> {\n"
                "        self.step += 1;\n",
            )
        ],
        (),
        (),
        ("booleval-true", "booleval-false"),
    ),
    "any codepage accepted": Mutation(
        HANDLERS,
        [("    if code_page != 0 {\n", "    if false {\n")],
        (),
        (),
        (
            "setcp-1",
            "setcp-minus-1",
            "setcp-5",
            "setcpx-1",
            "setcpx-20000",
            "setcpx-minus-32768",
            "setcp-1-caught-by-try",
        ),
    ),
    "SETCPX limited to 16384": Mutation(
        HANDLERS,
        [("i16::MIN as isize..=i16::MAX as isize", "i16::MIN as isize..=1 << 14")],
        (),
        (),
        ("setcpx-32767",),
    ),
    "SETGASLIMIT rejects 2^63 and more": Mutation(
        GAS,
        [
            (
                "            Sign::Plus => i64::from_int(x).unwrap_or(i64::MAX),\n",
                "            Sign::Plus => i64::from_int(x).ok()?,\n",
            )
        ],
        (),
        (),
        ("setgaslimit-2-pow-63", "setgaslimit-2-pow-200"),
    ),
    "SETGASLIMIT rejects large negative values": Mutation(
        GAS,
        [
            (
                "            Sign::Minus | Sign::NoSign => 0,\n",
                "            Sign::Minus | Sign::NoSign => i64::from_int(x).ok()?.min(0),\n",
            )
        ],
        (),
        (),
        ("setgaslimit-minus-2-pow-200",),
    ),
    "RUNVM before version 4": Mutation(
        CONTINUATION,
        [("    if engine.block_version() < 4 {\n", "    if engine.block_version() < 3 {\n")],
        ("runvm-version-3", "runvmx-version-3"),
    ),
    "RUNVM only from version 5": Mutation(
        CONTINUATION,
        [("    if engine.block_version() < 4 {\n", "    if engine.block_version() < 5 {\n")],
        ("runvm-version-4",),
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


def unit_test_passes(name, target):
    """Runs exactly the named Rust unit test; a build failure, or no test run, is not a result."""
    env = dict(os.environ, CARGO_TARGET_DIR=str(target))
    run = subprocess.run(
        ["cargo", "test", "--locked", "-q", "-p", "tos_vm", "--lib", "--", "--exact", name],
        cwd=CARGO,
        env=env,
        capture_output=True,
        text=True,
    )
    if run.returncode == 0 and "test result: ok. 1 passed; 0 failed" in run.stdout:
        return True
    if run.returncode != 0 and "test result: FAILED. 0 passed; 1 failed" in run.stdout:
        return False
    sys.exit(f"unit test {name} did not run exactly once (exit {run.returncode})")


def unit_tests_pass(target):
    tests = sorted({t for m in MUTATIONS.values() for t in m.tests})
    return [t for t in tests if not unit_test_passes(t, target)]


def endstate_output(scenarios, target):
    env = dict(os.environ, CARGO_TARGET_DIR=str(target))
    subprocess.run(
        ["cargo", "build", "--locked", "-q", "-p", "tos_vm", "--example", "vm-endstate"],
        cwd=CARGO,
        env=env,
        check=True,
        capture_output=True,
    )
    return subprocess.run(
        [str(Path(target) / "debug/examples/vm-endstate"), str(scenarios)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def endstate_differ(cpp, rust):
    """The end-state scenario ids whose Rust end state differs from the C++ one."""
    cpp_rows = [line.split("\t") for line in cpp.splitlines()]
    rust_rows = [line.split("\t") for line in rust.splitlines()]
    if [r[0] for r in cpp_rows] != [r[0] for r in rust_rows]:
        sys.exit("end-state output is incomplete")
    return {c[0] for c, r in zip(cpp_rows, rust_rows) if differences(c, r)}


def main(scenarios, cpp_output, target, endstate_scenarios, endstate_cpp_output, *flags):
    # Cargo runs in tosctl/src, so a relative target would build somewhere the driver is not
    # read from, and every mutation would run the unmutated driver.
    target = Path(target).resolve()
    listing = flags == ("--list",)
    cpp = Path(cpp_output).read_text()
    if rust_output(scenarios, target) != cpp:
        sys.exit("baseline differs: fix parity before measuring sensitivity")
    print("baseline: identical")
    endstate_cpp = Path(endstate_cpp_output).read_text()
    endstate_ids = [line.split("\t")[0] for line in endstate_cpp.splitlines()]
    if base := endstate_differ(endstate_cpp, endstate_output(endstate_scenarios, target)):
        sys.exit(f"end-state baseline differs: {sorted(base)}")
    print("end-state baseline: identical")
    # A test that already fails would make every mutation naming it look caught.
    if failing := unit_tests_pass(target):
        sys.exit(f"named unit tests fail before mutation: {failing}")
    print("named unit tests: pass")
    ids = [line.split("\t")[0] for line in cpp.splitlines()]
    failed = False
    for name, m in MUTATIONS.items():
        missing = [r for r in m.rows if r not in ids] + [
            r for r in m.endstate if r not in endstate_ids
        ]
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
            failing = [t for t in m.tests if not unit_test_passes(t, target)]
            endstate = endstate_differ(endstate_cpp, endstate_output(endstate_scenarios, target))
        finally:
            m.path.write_text(text)
        if len(out.splitlines()) != len(cpp.splitlines()):
            sys.exit(f"{name}: incomplete output is not mutation evidence")
        differ = {i for i, a, b in zip(ids, out.splitlines(), cpp.splitlines()) if a != b}
        if listing:
            print(
                f"{name}: {sorted(differ)}, end state {sorted(endstate)}, failing tests {failing}"
            )
            continue
        escaped = [r for r in m.rows if r not in differ] + [
            r for r in m.endstate if r not in endstate
        ]
        passing = [t for t in m.tests if t not in failing]
        ok = bool(m.rows or m.tests or m.endstate) and not escaped and not passing
        print(
            f"{name}: {'caught' if ok else 'ESCAPED'}"
            f" ({len(differ)} rows, {len(endstate)} end-state rows differ)"
        )
        if escaped:
            print(f"  named rows unchanged: {escaped}")
        if passing:
            print(f"  named tests still pass: {passing}")
        failed |= not ok
    if rust_output(scenarios, target) != cpp:
        sys.exit("restored baseline differs")
    if endstate_differ(endstate_cpp, endstate_output(endstate_scenarios, target)):
        sys.exit("restored end-state baseline differs")
    if failing := unit_tests_pass(target):
        sys.exit(f"named unit tests fail after restoring: {failing}")
    print("restored baseline: identical; named unit tests: pass")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main(*sys.argv[1:])
