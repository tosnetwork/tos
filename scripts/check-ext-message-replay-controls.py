#!/usr/bin/env python3
"""Run real checker/VM fixture against fixed code and the historical failure replay.

Requires a stopped build and the matching Linux source snapshot at /checkout.
Both host files and container copies are restored before the final test run.
"""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", required=True)
    parser.add_argument("--build-dir", default="/build-shadow")
    parser.add_argument("--replay-reference", default="47451af9d")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    paths = ["validator/impl/ext-message-checker.cpp", "validator/impl/ext-message-checker.hpp"]
    original = {p: (root / p).read_bytes() for p in paths}
    reference = subprocess.check_output(
        ["git", "rev-parse", args.replay_reference], cwd=root, text=True
    ).strip()
    replay = {
        p: subprocess.check_output(["git", "show", reference + ":" + p], cwd=root) for p in paths
    }
    if b"status_with_log" not in replay[paths[0]] or b"status_with_log" in original[paths[0]]:
        raise RuntimeError("expected fixed source and historical replay source")
    for relative in ["test/test-ext-message-pool.cpp", "test/pq-native/data/c04-pq-genesis.boc"]:
        actual = subprocess.check_output(
            ["docker", "exec", args.container, "sha256sum", "/checkout/" + relative], text=True
        ).split()[0]
        if actual != hashlib.sha256((root / relative).read_bytes()).hexdigest():
            raise RuntimeError("container fixture mismatch: " + relative)
    results = {}

    def run(name, command):
        with (output / (name + ".log")).open("wb") as log:
            result = subprocess.run(
                ["docker", "exec", args.container] + command,
                cwd=root,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        results[name] = result.returncode
        return result.returncode

    def build_and_test(name):
        for path in paths:
            subprocess.run(
                ["docker", "cp", str(root / path), args.container + ":/checkout/" + path],
                check=True,
            )
            subprocess.run(
                ["docker", "exec", args.container, "touch", "/checkout/" + path], check=True
            )
        if run(
            name + "-build",
            ["cmake", "--build", args.build_dir, "--target", "test-ext-message-pool", "-j", "2"],
        ):
            raise RuntimeError(name + " build failed")
        return run(name, [args.build_dir + "/test-ext-message-pool"])

    if build_and_test("baseline"):
        raise RuntimeError("baseline failed")
    try:
        for path in paths:
            (root / path).write_bytes(replay[path])
        if build_and_test("replay-enabled") == 0:
            raise RuntimeError("historical replay unexpectedly passed")
        failure = (output / "replay-enabled.log").read_text(errors="replace")
        if (
            "counter.starts is not equal to 1u (2 != 1)" not in failure
            or "counter.finishes is not equal to 1u (2 != 1)" not in failure
        ):
            raise RuntimeError("historical replay did not produce two actual VM executions")
    finally:
        for path in paths:
            (root / path).write_bytes(original[path])
        restored = build_and_test("restored")
        logs = {}
        for path in sorted(output.glob("*.log")):
            data = path.read_bytes()
            logs[path.name] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
        (output / "results.json").write_text(
            json.dumps(
                {
                    "fixed_sources": {
                        p: hashlib.sha256(v).hexdigest() for p, v in original.items()
                    },
                    "replay_reference": reference,
                    "returncodes": results,
                    "logs": logs,
                    "scope": "actual checker and VM, rejected empty-body config-contract message; not PQ signature load tests",
                },
                indent=2,
            )
            + "\n"
        )
        if restored:
            raise RuntimeError("restored tests failed")


if __name__ == "__main__":
    main()
