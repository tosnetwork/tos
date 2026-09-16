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

SEQUENCE = Path("validator/auth/native-config-sequence.cpp")
BINDING = Path("validator/auth/native-election-binding-transaction.cpp")
STATE = Path("validator/auth/native-config-state-host.cpp")
BINARY = Path("build-p0/test/validator-auth-implementation/test-p0-joined-commit")

UNINSTALLED = ('    if (claim.authorized() && claim.registry() != standing)\n'
               '      return Error{"config-sequence-uninstalled"};\n')
UNAUTHORIZED = ('  if (!claim.authorized())\n'
                '    return Error{"config-sequence-unauthorized"};\n')
REGISTRY = ('  if (claim.registry() != installed)\n'
            '    return Error{"config-sequence-registry"};\n')
PARAMETER = ('    if (!cs.fetch_int_to(32, declared) || declared != index)\n'
             '      return Error{"proposal-parameter"};\n')
COMPARE = ('    if (cs.fetch_ulong(1) != 1)\n'
           '      return Error{"proposal-compare"};\n')
PRECONDITION = ('    if (condition != previous)\n'
                '      return Error{"proposal-precondition"};\n')
VALUE = ('    if (hash(value) != proposed)\n'
         '      return Error{"proposal-value"};\n')
UNEXPECTED = ('    if (proposal.not_null())\n'
              '      return Error{"proposal-unexpected"};\n')
ABSENT = ('  if (proposal.is_null())\n'
          '    return Error{"proposal-absent"};\n')
BEFORE = ('    if (committed_parameter(earlier.value().configuration, claim.delta().index) != claim.delta().previous)\n'
          '      return Error{"config-sequence-parameter-before"};\n')
AFTER = ('    if (committed_parameter(committed.value().configuration, claim.delta().index) != claim.delta().proposed)\n'
         '      return Error{"config-sequence-parameter-after"};\n')
VALIDATORS = ('  if (claim.binds() && claim.validators() != committed_parameter(committed.value().configuration, 36))\n'
              '    return Error{"config-sequence-validators"};\n')
CHECKPOINT = ('  if (claim.checkpoint() != hash(committed.value().checkpoint))\n'
              '    return Error{"config-sequence-checkpoint"};\n')
# Opening from the parent state instead of the sequence: exactly what every
# transaction did before, and exactly as correct-looking on its own.
FROM_SEQUENCE = '      new NativeElectionBindingTransaction(sequence.accepted(), inputs.inclusion));'
FROM_PARENT = ('      new NativeElectionBindingTransaction(\n'
               '          NativeRegistryBlock::begin(\n'
               '              NativeRegistry::bootstrap(config.ok()->get_config_param(46), inputs.parent.seqno_)\n'
               '                  .value(),\n'
               '              inputs.inclusion)\n'
               '              .value(),\n'
               '          inputs.inclusion));')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--jobs", default="48")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    originals = {SEQUENCE: SEQUENCE.read_text(), BINDING: BINDING.read_text(), STATE: STATE.read_text()}
    mutations = [
        # A host that accepted an update the contract then did not write. The
        # account is unchanged, so nothing about the parameter is wrong; the
        # only evidence is that the two do not agree about what happened.
        (SEQUENCE, "uninstalled-claim-accepted", "joined-accepted-host-the-contract-ignored-refused",
         UNINSTALLED, "", []),
        # Parameter 46 moving with no host behind it -- a legacy proposal, or a
        # contract branch that wrote a well-formed registry nothing authorized.
        (SEQUENCE, "unauthorized-change-accepted", "joined-param46-change-without-host-refused",
         UNAUTHORIZED, "", ["joined-refusal-does-not-move-the-prefix"]),
        # The host accepted A and the contract committed B.
        (SEQUENCE, "wrong-registry-accepted", "joined-host-root-mismatch-refused", REGISTRY, "", []),
        # The parameter agrees and its second home does not. This is the pair
        # that made the registry unreadable one block after the first update.
        (SEQUENCE, "wrong-checkpoint-accepted", "joined-checkpoint-mismatch-refused", CHECKPOINT, "", []),
        # The contract handed one elected set and installing another. A binding
        # transaction moves no registry, so every parameter-46 check passes for
        # it whatever it wrote -- this is the only thing standing there.
        (SEQUENCE, "wrong-validator-set-accepted", "joined-bound-set-the-contract-replaced-refused",
         VALIDATORS, "", []),
        # The configuration proposal is not a virtual machine operand, so these
        # two comparisons are the only thing tying what the contract installed
        # to what the host was authorized for. A governance operation moves the
        # registry like any other, so every parameter-46 check passes for one
        # that installed a different proposal.
        (SEQUENCE, "installed-parameter-unchecked",
         "joined-configuration-parameter-the-contract-changed-refused", AFTER, "", []),
        (SEQUENCE, "prior-parameter-unchecked", "joined-configuration-parameter-unchanged-refused",
         BEFORE, "", []),
        # Each thing the operation and its proposal have to agree about. The
        # commit comparison is only as good as this binding: it checks that the
        # installed value matches the delta, and the delta comes from here.
        (SEQUENCE, "proposal-parameter-unchecked", "joined-proposal-for-another-parameter-refused",
         PARAMETER, '    if (!cs.fetch_int_to(32, declared))\n      return Error{"proposal-parameter"};\n', []),
        (SEQUENCE, "proposal-compare-optional", "joined-proposal-without-a-compare-and-swap-refused",
         COMPARE, "    if (cs.fetch_ulong(1) != 1) { return ConfigurationDelta{}; }\n", []),
        (SEQUENCE, "proposal-precondition-unchecked", "joined-proposal-stating-another-condition-refused",
         PRECONDITION, "", []),
        (SEQUENCE, "proposal-value-unchecked", "joined-proposal-carrying-another-value-refused", VALUE, "", []),
        (SEQUENCE, "stray-proposal-admitted", "joined-proposal-on-an-operation-that-takes-none-refused",
         UNEXPECTED, "", []),
        # The guard stops refusing rather than being deleted. Deleting it lets a
        # null reference reach the decoder and the process dies, which catches
        # nothing: a run that crashed reports no cases at all, and a case that
        # was never reported is indistinguishable from one that held.
        (SEQUENCE, "missing-proposal-admitted", "joined-governance-operation-without-a-proposal-refused",
         ABSENT, '  if (proposal.is_null())\n    return ConfigurationDelta{};\n', []),
        # A transaction that re-derives its prefix from the parent state. It
        # opens, it binds, and it is holding a registry this block already
        # replaced -- which is why the case reads the opened transaction's own
        # prefix rather than asking whether it opened.
        (BINDING, "prefix-rederived-from-parent", "joined-later-transaction-opens-on-the-committed-prefix",
         FROM_SEQUENCE, FROM_PARENT, []),
        # The account gate on the tick-tock authority. Without it the elector's
        # own tick-tock is handed a privileged host, because a tick-tock has no
        # message and so nothing upstream decided which account it is for.
        (STATE, "state-authority-account-ungated",
         "joined-state-authority-is-only-for-the-configuration-account",
         '  if (account != sequence.address())\n    return Error{"native-state-transaction-account"};\n', "", []),
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
        for source, guard, case, before, after, companions in mutations:
            original = originals[source]
            assert original.count(before) == 1, (guard, "anchor")
            changed = original.replace(before, after, 1)
            source.write_text(changed)
            reached = source.read_text() == changed
            compiled = build()
            broke, complete = [], False
            if compiled:
                result = outcomes()
                complete = set(result) == set(inventory) == declared()
                broke = sorted(name for name, held in result.items() if not held)
            source.write_text(original)
            restored = build() and all(outcomes().values())
            record = {"guard": guard, "case": case, "edit_reached_source": reached, "compiled": compiled,
                      "every_case_reported": complete, "cases_broken": broke,
                      "declared_companions": companions,
                      "only_declared_cases_broke": case in broke and set(broke) <= {case, *companions},
                      "restored_baseline": restored,
                      "source": str(source),
                      "source_unchanged": source.read_text() == original}
            records.append(record)
            print(json.dumps(record), flush=True)
            if not all(record[key] for key in ("edit_reached_source", "compiled", "every_case_reported",
                                               "only_declared_cases_broke", "restored_baseline",
                                               "source_unchanged")):
                failures += 1
    finally:
        for source, text in originals.items():
            source.write_text(text)

    (args.out / "mutations.json").write_text(json.dumps(records, indent=1) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
