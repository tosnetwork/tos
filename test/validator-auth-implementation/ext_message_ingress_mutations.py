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

ADMISSION = Path("validator/impl/ext-message-admission.h")

# The queue in front of the expensive check is sized from a delay. Putting a
# constant floor back under it is the defect that was there: the two agree only
# above about a hundred completions a second, and the slower the node gets the
# further a full queue departs from the delay it was supposedly sized for.
DELAY_ONLY = """  const double cap = completions_per_second * max_admission_queue_delay;"""
WITH_FLOOR = """  const double raw = completions_per_second * max_admission_queue_delay;
  const double cap = raw < 512.0 ? 512.0 : raw;"""

# The refusal is written against everything that is not a positive rate so that
# a rate which is not a number answers like one that is zero. Narrowing it to a
# sign test lets that rate multiply into a ceiling-sized queue.
UNMEASURABLE = """  if (!(completions_per_second > 0)) {"""
SIGN_ONLY = """  if (completions_per_second < 0) {"""

MUTATIONS = [
    ("ingress-carries-the-authority", "the-ingress-authority-reaches-the-instruction", CARRIES, DROPS, SOURCE),
    ("a-full-queue-never-implies-more-than-the-delay-allows",
     "a-full-queue-never-implies-more-than-the-delay-allows", DELAY_ONLY, WITH_FLOOR, ADMISSION),
    ("an-unmeasurable-rate-admits-no-queue",
     "an-unmeasurable-rate-admits-no-queue", UNMEASURABLE, SIGN_ONLY, ADMISSION),
]


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

    originals = {path: path.read_text() for path in {source for *_, source in MUTATIONS}}
    if not build(args.build):
        print("BASELINE-BUILD-FAILED", file=sys.stderr)
        return 1
    baseline = outcomes(run(args.build))
    if not baseline or not all(baseline.values()):
        print("BASELINE-NOT-PASSING", file=sys.stderr)
        return 1

    records, failures = [], 0
    try:
        for guard, case, before, after, source in MUTATIONS:
            original = originals[source]
            if original.count(before) != 1:
                print(f"ANCHOR-NOT-UNIQUE {guard} ({original.count(before)})", file=sys.stderr)
                failures += 1
                continue
            changed = original.replace(before, after, 1)
            source.write_text(changed)
            reached = source.read_text() == changed
            compiled = build(args.build)
            broke: list[str] = []
            complete = False
            if compiled:
                result = outcomes(run(args.build))
                # Every case must report. A run that stopped early would make a
                # case that never executed indistinguishable from one that held.
                complete = set(result) == set(baseline)
                broke = sorted(name for name, ok in result.items() if not ok)
            source.write_text(original)
            restored = build(args.build) and all(outcomes(run(args.build)).values())
            record = {"guard": guard, "case": case, "source": str(source), "edit_reached_source": reached,
                      "compiled": compiled, "every_case_reported": complete, "cases_broken": broke,
                      "only_the_named_case_broke": broke == [case], "restored_baseline": restored,
                      "source_unchanged": source.read_text() == original}
            records.append(record)
            print(json.dumps(record), flush=True)
            if not all(record[key] for key in ("edit_reached_source", "compiled", "every_case_reported",
                                               "only_the_named_case_broke", "restored_baseline", "source_unchanged")):
                failures += 1
    finally:
        for path, text in originals.items():
            path.write_text(text)

    (args.out / "mutations.json").write_text(json.dumps(records, indent=1) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
