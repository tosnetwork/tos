#!/usr/bin/env python3
"""Probe the real engine option parser without starting a node or opening a database."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True)
    parser.add_argument("--container")
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    prefix = ["docker", "exec", args.container] if args.container else []
    option = "--ext-message-work-profile"
    valid = "a" * 64 + ",2,1,1000000000,1,65535,512"
    cases = [
        ("valid", [option, valid], None),
        ("zero-root", [option, "0" * 64 + valid[64:]], "external admission"),
        ("uppercase", [option, "A" * 64 + valid[64:]], "lowercase hexadecimal"),
        ("overflow", [option, "a" * 64 + ",18446744073709551616,1,1,1,65535,512"], "Can't parse"),
        ("duplicate", [option, valid, option, valid], "must be specified only once"),
    ]
    results = {}
    failures = []
    for name, options, diagnostic in cases:
        # The option must precede help: help exits immediately with status 2.
        command = prefix + [args.engine] + options + ["--help"]
        completed = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30
        )
        data = completed.stdout
        (args.output_dir / (name + ".log")).write_bytes(data)
        output = data.decode(errors="replace")
        help_seen = "prints_help" in output
        passed = (
            (completed.returncode == 2 and help_seen and option in output)
            if diagnostic is None
            else (completed.returncode != 0 and diagnostic in output and not help_seen)
        )
        results[name] = {
            "command": command,
            "returncode": completed.returncode,
            "passed": passed,
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        }
        if not passed:
            failures.append(name)
    (args.output_dir / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    if failures:
        raise SystemExit("engine CLI checks failed: " + ", ".join(failures))
    print("Engine CLI: valid profile and four rejection boundaries passed")


if __name__ == "__main__":
    main()
