#!/usr/bin/env python3
"""Run the existing disk fixture under passive production-function breakpoints.

No admission objects are assembled here. Missing symbols or trace delivery fail
closed. The trace establishes only the functions listed below, not all side
effects or a complete call graph. Use a fresh output directory for each run.
"""
import json
import os
from pathlib import Path
import subprocess
import sys


def check(directory):
    expected = {
        "bootstrap": (0, ["preinit", "validator_set", "old_state"]),
        "account_binding_refused": (2, ["preinit", "configuration", "adapter"]),
        "account_config_failure": (2, ["preinit", "configuration"]),
        "account_state_corrupt": (2, ["preinit", "configuration"]),
        "account_no_stats": (2, []),
    }
    expected_files = {name + ".result.trace.json" for name in expected}
    actual_files = {path.name for path in directory.glob("*.result.trace.json")}
    observed = {}
    for name, (code, events) in expected.items():
        value = json.loads((directory / (name + ".result.trace.json")).read_text())
        counts = {site: events.count(site) for site in
                  ("preinit", "configuration", "adapter", "validator_set", "old_state")}
        if value != {"exit_code": code, "counts": counts, "events": events}:
            raise RuntimeError(json.dumps({"guard": "production-frontier", "query": name,
                                           "expected_counts": counts, "observed": value}))
        observed[name] = value
    if actual_files != expected_files:
        raise RuntimeError(json.dumps({"guard": "trace-inventory",
                                       "expected": sorted(expected_files),
                                       "observed": sorted(actual_files)}))
    print(json.dumps({"guard": "production-frontier", "observed": observed}, indent=2))
    return 0


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--check":
        return check(Path(sys.argv[2]))
    binary = Path(os.environ["WORKCHAIN_FRONTIER_BINARY"]).resolve(strict=True)
    output = Path(os.environ["WORKCHAIN_FRONTIER_OUTPUT"]).resolve(strict=True)
    args = sys.argv[1:]
    if "--query-result" not in args:
        return subprocess.run([str(binary), *args], check=False).returncode
    label = Path(args[args.index("--query-result") + 1]).name
    trace = output / (label + ".trace.json")
    if trace.exists():
        raise RuntimeError("refusing to reuse an earlier trace")
    env = dict(os.environ, WORKCHAIN_FRONTIER_TRACE=str(trace))
    result = subprocess.run([
        "gdb", "--batch", "--return-child-result", "--quiet",
        "-x", str(Path(__file__).with_suffix(".gdb")), "--args", str(binary), *args,
    ], env=env, check=False)
    if not trace.exists():
        raise RuntimeError("debugger did not confirm trace delivery")
    record = json.loads(trace.read_text())
    if record["exit_code"] != result.returncode:
        raise RuntimeError("debugger exit differs from observed inferior exit")
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
