#!/usr/bin/env python3
"""Verify node option validation, including a deletion control on its real setter."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--boundary", choices=["setter", "parser-validation", "parser-canonical"], default="setter"
    )
    parser.add_argument(
        "--container", help="Optional Docker snapshot; omit for a native build of this checkout"
    )
    parser.add_argument("--build-dir", default="/build-shadow")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    relative_source = (
        "validator/validator-options.hpp"
        if args.boundary == "setter"
        else "validator/admission-work-profile.cpp"
    )
    path = root / relative_source
    original = path.read_bytes()
    for relative in (
        [
            "test/test-validator-options.cpp",
            "validator/admission-work-profile.h",
            "validator/validator.h",
        ]
        if args.container
        else []
    ):
        actual = subprocess.check_output(
            ["docker", "exec", args.container, "sha256sum", "/checkout/" + relative], text=True
        ).split()[0]
        if actual != hashlib.sha256((root / relative).read_bytes()).hexdigest():
            raise RuntimeError("container source mismatch: " + relative)
    anchor = b"    TRY_STATUS(profile.validate());"
    replacement = b"    // Controlled deletion of option validation."
    expected_failure = "invalid admission profile was installed"
    if args.boundary == "parser-validation":
        anchor = b"  TRY_STATUS(profile.validate());"
        replacement = b"  // Controlled deletion of parsed profile validation."
        expected_failure = "invalid admission CLI profile accepted: zero-root"
    elif args.boundary == "parser-canonical":
        anchor = b"!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))"
        replacement = b"c == '\\0'"
        expected_failure = "invalid admission CLI profile accepted: uppercase-hash"
    if original.count(anchor) != 1:
        raise RuntimeError("expected one option validation anchor")
    results = {}

    def run(name, command):
        with (output / (name + ".log")).open("wb") as log:
            prefix = ["docker", "exec", args.container] if args.container else []
            result = subprocess.run(
                prefix + command, cwd=root, stdout=log, stderr=subprocess.STDOUT
            )
        results[name] = result.returncode
        return result.returncode

    def check(name):
        if args.container:
            subprocess.run(
                ["docker", "cp", str(path), args.container + ":/checkout/" + relative_source],
                check=True,
            )
            subprocess.run(
                ["docker", "exec", args.container, "touch", "/checkout/" + relative_source],
                check=True,
            )
        if run(
            name + "-build",
            ["cmake", "--build", args.build_dir, "--target", "test-validator-options", "-j", "2"],
        ):
            raise RuntimeError(name + " build failed")
        return run(name, [args.build_dir + "/test-validator-options"])

    if check("baseline"):
        raise RuntimeError("baseline failed")
    try:
        path.write_bytes(original.replace(anchor, replacement))
        if check("skip-validation") == 0:
            raise RuntimeError("invalid profile was accepted without a failing test")
        if expected_failure not in (output / "skip-validation.log").read_text():
            raise RuntimeError("mutation failed outside the intended option boundary")
    finally:
        path.write_bytes(original)
        restored = check("restored")
        logs = {}
        for item in sorted(output.glob("*.log")):
            data = item.read_bytes()
            logs[item.name] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
        (output / "results.json").write_text(
            json.dumps(
                {
                    "boundary": args.boundary,
                    "source": relative_source,
                    "source_sha256": hashlib.sha256(original).hexdigest(),
                    "returncodes": results,
                    "logs": logs,
                },
                indent=2,
            )
            + "\n"
        )
        if restored:
            raise RuntimeError("restored test failed")


if __name__ == "__main__":
    main()
