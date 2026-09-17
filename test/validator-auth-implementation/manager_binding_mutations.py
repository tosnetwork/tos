"""Compile session confirmation guard removals and require named assertion failures.

The confirmation decides whether a validator group may be created at all, so
each rule it applies has to be one a case can observe being removed. Two of them
are removals rather than rewrites: the state admission, and the roster rule that
is the only thing said about the pairing of a state with a set.

Each mutation is named for the first case that fails without it, because the
suite stops at its first failure and that name is what it prints.
"""
import argparse
import json
import subprocess
from pathlib import Path

from mutation_support import replace_once

MUTATIONS = [
    # The regression this file exists to prevent, written as the code that had
    # it: derive the committee, and if it refuses, fall back to what the state
    # says on its own. Every rule the state settles still holds, so the cases
    # about counts, bindings and duplicates stay refused; the registry's rules
    # are what stop being applied, and a set carrying a binding the registry
    # never issued is confirmed again.
    ("a-binding-the-registry-never-issued-is-refused",
     """  if (!committee.ok())
    return committee.error();""",
     """  if (!committee.ok()) {
    auto admitted = admit_masterchain_state(masterchain_state);
    if (!admitted.ok())
      return admitted.error();
    return true;
  }"""),
    # Without the roster rule an admissible state carries any roster offered
    # beside it, because every other rule here is about the state.
    ("a-roster-from-another-state-is-refused",
     """  if (committee.value().transport_order() != validator_set->export_vector())
    return Error{"manager-session-roster"};""",
     ""),
    # The committee has to be derived for the session this set would run. A
    # committee derived for another catchain sequence selects other members, so
    # what the manager seats is not what was admitted.
    ("manager-identity-is-confirmed",
     "validator_set->get_catchain_seqno(), budget);",
     "0, budget);"),
]


def main(args):
    build = args.build.resolve()
    folder = build / "test/validator-auth-implementation"
    source = folder / "mutated-manager-session-binding.cpp"
    original = source.read_text()
    target = "test-p0-manager-session-binding-mutant"
    report = []

    def run(text):
        source.write_text(text)
        built = subprocess.run(["cmake", "--build", str(build), "--target", target, "-j2"],
                               capture_output=True, text=True)
        if built.returncode:
            raise RuntimeError(built.stdout + built.stderr)
        return subprocess.run([str(folder / target)], capture_output=True, text=True)

    for label, before, after in MUTATIONS:
        try:
            baseline = run(original)
            assert baseline.returncode == 0, baseline.stderr
            result = run(replace_once(original, before, after))
            # The suite stops at its first failure and prints that case's name
            # last. The stream also carries whatever the validator-set code
            # logged while the fixture built its rosters, so the verdict is the
            # final line rather than the whole of stderr -- still the exact
            # name, so a mutation killed by a different case does not pass.
            verdict = [line for line in result.stderr.splitlines() if line.strip()][-1:]
            assert result.returncode == 1 and verdict == ["ASSERTION: " + label], (
                label, result.returncode, result.stderr)
            report.append(dict(guard=label, compiled=True, assertion_failed=True))
            print("KILLED:", label, flush=True)
        finally:
            restored = run(original)
            assert restored.returncode == 0, restored.stderr
    args.out.write_text(json.dumps(dict(manager_binding_mutations=report, restored_baselines=True), indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    main(parser.parse_args())
