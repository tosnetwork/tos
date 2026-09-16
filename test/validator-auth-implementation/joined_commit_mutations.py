"""Remove each binding between the host's candidate and the account's commit.

The sequence exists because a host staging a prefix and a contract writing one
are two descriptions of a single fact. Every guard below is the comparison that
makes them one; deleting it leaves both halves individually correct and the pair
free to disagree, which is the shape that has already produced four production
defects in this tree.

Each guard is removed on its own. The guards shadow one another for most inputs
-- a claim-less commit also names a registry nothing accepted -- so the cases
assert the refusal reason rather than the refusal, and a mutation that left the
behaviour intact but moved the answer to a later guard is still a kill.

The reported case set is compared against the baseline's on every mutation. A
case that stops being reported is a harness defect, not a survivor: cases have
twice vanished under mutation in this tree instead of failing.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

SOURCE = Path("validator/auth/native-config-sequence.cpp")
BINARY = Path("build-p0/test/validator-auth-implementation/test-p0-joined-commit")

UNINSTALLED = ('    if (claim.authorized() && claim.registry() != standing)\n'
               '      return Error{"config-sequence-uninstalled"};\n')
UNAUTHORIZED = ('  if (!claim.authorized())\n'
                '    return Error{"config-sequence-unauthorized"};\n')
REGISTRY = ('  if (claim.registry() != installed)\n'
            '    return Error{"config-sequence-registry"};\n')
CHECKPOINT = ('  if (claim.checkpoint() != hash(committed.value().checkpoint))\n'
              '    return Error{"config-sequence-checkpoint"};\n')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--jobs", default="48")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    mutations = [
        # A host that accepted an update the contract then did not write. The
        # account is unchanged, so nothing about the parameter is wrong; the
        # only evidence is that the two do not agree about what happened.
        ("uninstalled-claim-accepted", "joined-accepted-host-the-contract-ignored-refused",
         UNINSTALLED, "", []),
        # Parameter 46 moving with no host behind it -- a legacy proposal, or a
        # contract branch that wrote a well-formed registry nothing authorized.
        ("unauthorized-change-accepted", "joined-param46-change-without-host-refused",
         UNAUTHORIZED, "", ["joined-refusal-does-not-move-the-prefix"]),
        # The host accepted A and the contract committed B.
        ("wrong-registry-accepted", "joined-host-root-mismatch-refused", REGISTRY, "", []),
        # The parameter agrees and its second home does not. This is the pair
        # that made the registry unreadable one block after the first update.
        ("wrong-checkpoint-accepted", "joined-checkpoint-mismatch-refused", CHECKPOINT, "", []),
        # The gathered-coordinate refusal is not listed here on purpose. The
        # sequence does not carry its own copy of that rule: the registry
        # replay refuses a successor that is not the parent's next one, and its
        # lock lives with native_registry_mutations.py. A copy here was deleted
        # after a mutation showed no case could tell it was gone.
    ]

    def build() -> bool:
        return subprocess.run(["cmake", "--build", "build-p0", "--target", "test-p0-joined-commit",
                               "-j" + args.jobs], capture_output=True, text=True, check=False).returncode == 0

    def outcomes() -> dict[str, bool]:
        result = subprocess.run([str(BINARY)], capture_output=True, text=True, check=False)
        return {line.split(" ", 1)[1]: line.startswith("CASE_PASS ")
                for line in result.stdout.splitlines() if line.startswith("CASE_")}

    def declared() -> set[str]:
        result = subprocess.run([str(BINARY)], capture_output=True, text=True, check=False)
        return {line.split(" ", 1)[1] for line in result.stdout.splitlines() if line.startswith("MANIFEST ")}

    if not build():
        print("BASELINE-BUILD-FAILED", file=sys.stderr)
        return 1
    inventory = outcomes()
    manifest = declared()
    if not inventory or not all(inventory.values()):
        print("BASELINE-NOT-PASSING", file=sys.stderr)
        return 1
    # The manifest the binary prints and the cases it runs must be the same set,
    # or "every case reported" is being measured against a list that already
    # agrees with whatever ran.
    if set(inventory) != manifest:
        print("BASELINE-MANIFEST-MISMATCH", file=sys.stderr)
        return 1

    records, failures = [], 0
    try:
        for guard, case, before, after, companions in mutations:
            assert original.count(before) == 1, (guard, "anchor")
            changed = original.replace(before, after, 1)
            SOURCE.write_text(changed)
            reached = SOURCE.read_text() == changed
            compiled = build()
            broke, complete = [], False
            if compiled:
                result = outcomes()
                complete = set(result) == set(inventory) == declared()
                broke = sorted(name for name, held in result.items() if not held)
            SOURCE.write_text(original)
            restored = build() and all(outcomes().values())
            record = {"guard": guard, "case": case, "edit_reached_source": reached, "compiled": compiled,
                      "every_case_reported": complete, "cases_broken": broke,
                      "declared_companions": companions,
                      "only_declared_cases_broke": case in broke and set(broke) <= {case, *companions},
                      "restored_baseline": restored,
                      "source_unchanged": SOURCE.read_text() == original}
            records.append(record)
            print(json.dumps(record), flush=True)
            if not all(record[key] for key in ("edit_reached_source", "compiled", "every_case_reported",
                                               "only_declared_cases_broke", "restored_baseline",
                                               "source_unchanged")):
                failures += 1
    finally:
        SOURCE.write_text(original)

    (args.out / "mutations.json").write_text(json.dumps(records, indent=1) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
