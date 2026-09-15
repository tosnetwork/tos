"""Remove one guard of election binding at a time.

A wrong binding is not caught here by anything downstream that can name it:
committee derivation refuses the set, but only as a whole. So every guard below
has to have a case, and the case has to be the only one that fails.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

SOURCE = Path("validator/auth/native-election-binding.cpp")
BINARY = Path("build-p0/test/validator-auth-implementation/test-p0-election-binding")

MUTATIONS = [
    ("owner-decides", "another-members-identity-is-refused",
     '      if (found.value().owner_workchain_ != tos::masterchainId ||\n'
     '          found.value().owner_address_ != named->second.staking_account)\n'
     '        return Error{"election-binding-owner"};',
     ''),
    ("registration-required", "unregistered-identity-is-refused",
     '      if (!found.ok())\n        return Error{"election-binding-unregistered"};',
     '      if (!found.ok())\n        return Error{"election-binding-owner"};'),
    ("seated-once", "one-identity-twice-is-refused",
     '      if (!identities.insert(found.value().identity_).second || !stakes.insert(found.value().stake_id_).second)\n'
     '        return Error{"election-binding-duplicate"};',
     ''),
    ("counts-agree", "bindings-for-members-that-do-not-exist-are-refused",
     '    if (bindings.size() != set.total)\n      return Error{"election-binding-incomplete"};',
     ''),
    ("address-required", "member-without-an-address-is-refused",
     '      if (!member.value().has_address || member.value().weight == 0)\n'
     '        return Error{"election-binding-descriptor"};',
     ''),
    ("weight-survives", "declared-weight-must-survive",
     '    if (weight != set.total_weight)\n      return Error{"election-binding-weight"};',
     ''),
    ("entry-width", "an-entry-with-trailing-data-is-refused",
     '      if (field.size() != 512 || field.size_refs() != 0 ||',
     '      if (field.size() < 512 || field.size_refs() != 0 ||'),
    ("nothing-past-the-end", "an-entry-past-the-end-is-refused",
     '    if (present != decoded.size())\n      return Error{"election-binding-shape"};',
     ''),
    ("derivation-asked", "a-consensus-key-that-is-also-a-registry-key-is-refused",
     '      auto keys = committee_identity_keys(found.value(), registry, anchor, consensus);\n'
     '      if (!keys.ok())\n'
     '        return keys.error();',
     ''),
    ("binding-attached", "bound-set-carries-the-registry-binding",
     '      td::Ref<vm::Cell> binding;\n'
     '      if (!block::gen::t_ValidatorAuthBinding.cell_pack_validator_auth_binding(\n'
     '              binding, td::Bits256(td::ConstBitPtr(found.value().identity_.data())),\n'
     '              td::Bits256(td::ConstBitPtr(found.value().stake_id_.data()))))\n'
     '        return Error{"election-binding-pack"};',
     '      td::Ref<vm::Cell> binding;\n'
     '      if (!block::gen::t_ValidatorAuthBinding.cell_pack_validator_auth_binding(\n'
     '              binding, td::Bits256(td::ConstBitPtr(found.value().stake_id_.data())),\n'
     '              td::Bits256(td::ConstBitPtr(found.value().identity_.data()))))\n'
     '        return Error{"election-binding-pack"};'),
]


def build() -> bool:
    return subprocess.run(["cmake", "--build", "build-p0", "--target", "test-p0-election-binding", "-j48"],
                          capture_output=True, text=True, check=False).returncode == 0


def run() -> subprocess.CompletedProcess:
    return subprocess.run([str(BINARY)], capture_output=True, text=True, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    baseline = run()
    if baseline.returncode != 0:
        print("BASELINE-NOT-PASSING")
        return 1
    cases = [line.split()[1] for line in baseline.stdout.splitlines() if line.startswith("CASE_PASS")]

    records, failures = [], 0
    for guard, case, before, after in MUTATIONS:
        if original.count(before) != 1:
            print(f"ANCHOR-NOT-UNIQUE {guard} ({original.count(before)})")
            failures += 1
            continue
        SOURCE.write_text(original.replace(before, after, 1))
        reached = before not in SOURCE.read_text()
        compiled = build()
        named, earlier = False, False
        if compiled:
            result = run()
            output = result.stdout + result.stderr
            named = result.returncode != 0 and case in output
            earlier = all(f"CASE_PASS {name}" in output for name in cases[:cases.index(case)])
        SOURCE.write_text(original)
        restored = build() and run().returncode == 0
        record = {"guard": guard, "case": case, "edit_reached_source": reached, "compiled": compiled,
                  "named_assertion_failed": named, "no_earlier_case_failed": earlier,
                  "restored_baseline": restored, "source_unchanged": SOURCE.read_text() == original}
        records.append(record)
        print(json.dumps(record))
        if not all(v for k, v in record.items() if k not in ("guard", "case")):
            failures += 1

    (args.out / "mutations.json").write_text(json.dumps(records, indent=1))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
