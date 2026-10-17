#!/usr/bin/env python3
"""Linux behavior control for the real read-only proof HTTP route."""

import argparse
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = root / "validator-engine/json-rpc-server.cpp"
    baseline = source.read_text()
    build = args.build_dir.resolve()
    target = [
        str(build / "test-json-rpc-transport"),
        "--filter",
        "proof_relay_refuses_send_and_nested_queries_without_backend",
    ]
    compile_command = [
        "cmake",
        "--build",
        str(build),
        "--target",
        "test-json-rpc-transport",
        "-j",
        "2",
    ]
    subprocess.run(target, check=True)
    try:
        needle = '{"getProofQuery", G,'
        if baseline.count(needle) != 1:
            raise RuntimeError("Expected exactly one proof RPC route")
        source.write_text(baseline.replace(needle, '{"getProofQueryRemoved", G,', 1))
        subprocess.run(compile_command, check=True)
        # The engine's debug log can carry raw bytes, so the output is read as bytes,
        # kept verbatim, and decoded only to look for the test's name.
        result = subprocess.run(target, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (build / "proof-query-route-control.log").write_bytes(result.stdout)
        output = result.stdout.decode("utf-8", errors="backslashreplace")
        if result.returncode == 0:
            raise RuntimeError("Proof route removal was not detected")
        if "proof_relay_refuses_send_and_nested_queries_without_backend" not in output:
            raise RuntimeError("Named runtime test did not report failure")
        print("Compiled proof-route removal caused the named HTTP test to fail")
    finally:
        source.write_text(baseline)
    subprocess.run(compile_command, check=True)
    subprocess.run(target, check=True)


if __name__ == "__main__":
    main()
