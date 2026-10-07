#!/usr/bin/env python3
"""Compile and execute raw/symbolic ML-DSA-44 spellings at a cell boundary.

Raw Fift insertion is intentionally still allowed. The boundary failure is an
assembler error, not a TOL parse error or a signature authorization failure.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def run(argv):
    return subprocess.run(argv, capture_output=True, text=True, timeout=30)


def byte_chain(data):
    """Canonical 127-byte chunks, built tail first without external fixtures."""
    if not data:
        return "<b b>"
    chunks = [data[offset : offset + 127] for offset in range(0, len(data), 127)]
    result = f"<b x{{{chunks[-1].hex()}}} s, b>"
    for chunk in reversed(chunks[:-1]):
        result += f" <b x{{{chunk.hex()}}} s, swap ref, b>"
    return result


def main():
    compiler, fift = map(os.path.abspath, sys.argv[1:3])
    fixtures = Path(__file__).resolve().parents[1] / "test/pq-mldsa44/fixtures.json"
    corpus = json.loads(fixtures.read_text())
    vector = next(case for case in corpus["cases"] if case["id"] == "openssl-auth-commitment")
    valid = tuple(
        bytes.fromhex(vector[field]) for field in ("messageHex", "contextHex", "signatureHex")
    ) + (bytes.fromhex(corpus["publicKeyHex"]),)
    invalid = (b"", b"", bytes(2420), bytes(1312))
    with tempfile.TemporaryDirectory(prefix="tol-raw-capacity-") as directory:
        root = Path(directory)
        for boundary in (False, True):
            for raw in (False, True):
                name = f"{'boundary' if boundary else 'room'}-{'raw' if raw else 'symbolic'}"
                opcode = "x{F93100} s," if raw else "PQCHECKSIG_MLDSA44"
                # Start a continuation explicitly: exactly 1000 bits of NOPs
                # remain before the 24-bit opcode, independent of TOL's prologue.
                prefix = "@| { NOP } 125 times " if boundary else ""
                source = root / f"{name}.tol"
                compiled = root / f"{name}.fif"
                source.write_text(
                    "fun checkOpcode(message: cell, context: cell, signature: cell, publicKey: cell): bool\n"
                    f'    asm "{prefix}{opcode}"\n'
                    "@method_id(100001)\n"
                    "fun check(message: cell, context: cell, signature: cell, publicKey: cell): bool {\n"
                    "    return checkOpcode(message, context, signature, publicKey);\n"
                    "}\n"
                    "fun onInternalMessage(in: InMessage) {}\n"
                )
                frontend = run([compiler, "-o", str(compiled), str(source)])
                assert frontend.returncode == 0, (name, frontend.stderr)
                runner = root / f"{name}-runner.fif"
                # An independent signature vector and a well-sized invalid
                # signature prevent constant-return implementations from passing.
                runner.write_text(
                    f'"{compiled}" include <s constant code\n'
                    + "".join(
                        " ".join(byte_chain(data) for data in inputs)
                        + ' 100001 code 1 runvmx abort"nonzero VM exit" .s cr drop\n'
                        for inputs in (valid, invalid)
                    )
                )
                result = run([fift, str(runner)])
                if boundary and raw:
                    assert (
                        result.returncode != 0 and "slice does not fit into cell" in result.stderr
                    ), (name, result.stdout, result.stderr)
                else:
                    assert result.returncode == 0 and result.stdout.split() == ["-1", "0"], (
                        name,
                        result.stdout,
                        result.stderr,
                    )
                print(f"RAW_OPCODE_CAPACITY {name} PASS")
    print("RAW_OPCODE_CAPACITY_OK: 4 cases")


if __name__ == "__main__":
    main()
