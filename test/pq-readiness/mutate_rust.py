#!/usr/bin/env python3
"""A compiler error is not a killed Rust VM mutation."""

import argparse
import json
import subprocess
from pathlib import Path

from compare import check

ROOT = Path(__file__).resolve().parents[2]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--scenarios", type=Path, required=True)
    p.add_argument("--cpp", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    source = ROOT / "tosctl/src/vm/src/executor/pq.rs"
    # The version gate is the opcodes' codepage 0 entry, and an invalid opcode is charged by
    # the engine as the C++ VM's consume_gas does: checked at once only from version 4.
    table = ROOT / "tosctl/src/vm/src/executor/engine/cp0_prefixes.rs"
    core = ROOT / "tosctl/src/vm/src/executor/engine/core.rs"
    consume_gas = "        if self.block_version >= 4 {\n            self.try_use_gas(gas)"
    mutants = [
        (
            "verification",
            source,
            "status == invalid_signature {\n        false",
            "status == invalid_signature {\n        true",
        ),
        ("version", table, "    (0xf93100, 24, 16),", "    (0xf93100, 24, 0),"),
        (
            "signature-charge",
            source,
            "MAX_MESSAGE_BYTES)?;\n    engine.register_chksgn_call()?;\n    if key.len()",
            "MAX_MESSAGE_BYTES)?;\n    if key.len()",
        ),
        ("byte-gas", source, "const BYTE_GAS: i64 = 0;", "const BYTE_GAS: i64 = 1;"),
        ("canonical-chunk", source, "(refs != 0 && size != CHUNK_BYTES)", "(false)"),
        (
            "preactivation-gas",
            core,
            consume_gas,
            consume_gas.replace("self.block_version >= 4", "false"),
        ),
    ]
    build = [
        "cargo",
        "build",
        "--manifest-path",
        str(ROOT / "tosctl/src/Cargo.toml"),
        "--locked",
        "--release",
        "-p",
        "tos_vm",
        "--example",
        "pq-parity",
    ]
    exe = ROOT / "tosctl/src/target/release/examples/pq-parity"
    transcript = a.out.with_suffix(".tsv")
    reports = []

    def execute():
        subprocess.run(build, cwd=ROOT, check=True)
        with transcript.open("w") as f:
            subprocess.run([str(exe), str(a.scenarios.resolve())], stdout=f, check=True)

    execute()
    check(a.scenarios, a.cpp, transcript)
    for name, path, before, after in mutants:
        original = path.read_text()
        if original.count(before) != 1:
            raise ValueError("guard must occur once: " + name)
        try:
            path.write_text(original.replace(before, after))
            execute()  # Must compile and finish; a crash/error is not a kill.
            try:
                check(a.scenarios, a.cpp, transcript)
            except ValueError:
                reports.append({"guard": name, "compiled": True, "killed": True})
            else:
                raise RuntimeError("surviving mutation: " + name)
        finally:
            path.write_text(original)
        execute()
        check(a.scenarios, a.cpp, transcript)
    a.out.write_text(json.dumps(reports, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
