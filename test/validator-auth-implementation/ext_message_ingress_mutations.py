"""Remove the authority the message pool runs an update with.

The defect this guards against had no symptom. Admission executes the
destination contract, the configuration contract applies a registry update
before accepting the message, and a run offered no authority throws the
privileged instruction's refusal inside the gas credit. Every valid update was
rejected at the door, and a chain that refuses every update looks exactly like
a chain nobody submits updates to.

So the mutation is the defect: drop the authority on its way to the
transaction. The named case must fail, and the other two must not -- an
ordinary message is unaffected, and a message that needs an authority and is
offered none is still refused.

This runs where the validator library links. The P0 job configures without the
storage backend and compiles the ingress translation units on their own, so the
tree this uses is named by --build rather than assumed.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

SOURCE = Path("validator/impl/external-message.cpp")

CARRIES = """                                                        &exec_config.serialize_config, true, lt, nullptr,
                                                        std::move(validator_auth_host));"""
DROPS = """                                                        &exec_config.serialize_config, true, lt, nullptr, {});"""

MUTATIONS = [("ingress-carries-the-authority", "the-ingress-authority-reaches-the-instruction", CARRIES, DROPS)]


def build(tree: str) -> bool:
    return subprocess.run(["cmake", "--build", tree, "--target", "test-p0-ext-message-ingress", "-j48"],
                          capture_output=True, text=True, check=False).returncode == 0


def run(tree: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([f"{tree}/test/validator-auth-implementation/test-p0-ext-message-ingress"],
                          capture_output=True, text=True, check=False)


def outcomes(result: subprocess.CompletedProcess[str]) -> dict[str, bool]:
    return {line.split(" ", 1)[1]: line.startswith("CASE_PASS ")
            for line in result.stdout.splitlines() if line.startswith("CASE_")}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", default="build-rocks")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    if not build(args.build):
        print("BASELINE-BUILD-FAILED", file=sys.stderr)
        return 1
    baseline = outcomes(run(args.build))
    if not baseline or not all(baseline.values()):
        print("BASELINE-NOT-PASSING", file=sys.stderr)
        return 1

    records, failures = [], 0
    try:
        for guard, case, before, after in MUTATIONS:
            if original.count(before) != 1:
                print(f"ANCHOR-NOT-UNIQUE {guard} ({original.count(before)})", file=sys.stderr)
                failures += 1
                continue
            changed = original.replace(before, after, 1)
            SOURCE.write_text(changed)
            reached = SOURCE.read_text() == changed
            compiled = build(args.build)
            broke: list[str] = []
            complete = False
            if compiled:
                result = outcomes(run(args.build))
                # Every case must report. A run that stopped early would make a
                # case that never executed indistinguishable from one that held.
                complete = set(result) == set(baseline)
                broke = sorted(name for name, ok in result.items() if not ok)
            SOURCE.write_text(original)
            restored = build(args.build) and all(outcomes(run(args.build)).values())
            record = {"guard": guard, "case": case, "edit_reached_source": reached, "compiled": compiled,
                      "every_case_reported": complete, "cases_broken": broke, "only_the_named_case_broke": broke == [case],
                      "restored_baseline": restored, "source_unchanged": SOURCE.read_text() == original}
            records.append(record)
            print(json.dumps(record), flush=True)
            if not all(record[key] for key in ("edit_reached_source", "compiled", "every_case_reported",
                                               "only_the_named_case_broke", "restored_baseline", "source_unchanged")):
                failures += 1
    finally:
        SOURCE.write_text(original)

    (args.out / "mutations.json").write_text(json.dumps(records, indent=1) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
