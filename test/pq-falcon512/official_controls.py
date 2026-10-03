#!/usr/bin/env python3
"""Prove official-KAT checks reject compiled bogus verifiers and an inert suite."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from official_kat import ROOT, RSP, check_api, records, require


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--suite", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    source = """#include <stddef.h>
int falcon_verify(const void *sig, size_t sl, int type, const void *pk,
    size_t pl, const void *msg, size_t ml, void *tmp, size_t tl) {
  return RESULT;
}
int falcon_make_public(void *pk, size_t pl, const void *sk, size_t sl,
    void *tmp, size_t tl) { return 0; }
"""
    flags = ["-dynamiclib"] if sys.platform == "darwin" else ["-shared", "-fPIC"]
    compiler = os.environ.get("CC", "cc")
    results = []
    for name, result, expected in [
        ("always-accept", "0", "altered message accepted at count 0"),
        ("always-reject", "-3", "official signature rejected at count 0"),
        ("empty-suite", None, "official 512 KAT skipped, incomplete or digest mismatch"),
    ]:
        c = out / f"{name}.c"
        binary = out / (name + (".dylib" if sys.platform == "darwin" else ".so"))
        c.write_text(
            source.replace("RESULT", result) if result else "int main(void) { return 0; }\n"
        )
        command = [compiler, *(flags if result else []), str(c), "-o", str(binary)]
        subprocess.run(command, check=True, capture_output=True, text=True)
        library = binary if result else args.library.resolve()
        suite = args.suite.resolve() if result else binary
        run = subprocess.run(
            [
                sys.executable,
                str(ROOT / "test/pq-falcon512/official_kat.py"),
                "--library",
                str(library),
                "--suite",
                str(suite),
                "--out",
                str(out / name),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        require(run.returncode == 1 and expected in run.stderr, f"control was not killed: {name}")
        results.append(
            dict(
                name=name,
                compiled=True,
                killed=True,
                expected_failure=expected,
                checker_exit=run.returncode,
                binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                compile_command=command,
            )
        )
    check_api(args.library, records(RSP.read_bytes()))
    report = dict(
        success=True,
        baseline_api_passed=True,
        scope="compiled sensitivity controls for the official KAT checker",
        controls=results,
    )
    (out / "official-controls.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("PASS: 3 compiled official-KAT controls killed; real API baseline passed")


if __name__ == "__main__":
    main()
