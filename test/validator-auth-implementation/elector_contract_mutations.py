"""Remove one part of the elector's activation behaviour at a time.

Activation is read from Config8. Four things follow from it, and each is
separately removable, so each is removed separately:

  the refusal of a stake that names no identity,
  the exclusion of such a record from selection,
  the refund that pays an excluded record back,
  and the silence of an inactive election.

The refund is the one that hides. A chain that activates already has stakes in
members that named nothing; refusing new ones does nothing about them, and a
selection filter alone would strand them. Only the case that elects over a
legacy record and then reads the credits can tell the two apart.

Compiles the contract the way the suite does and requires every case to report,
so a case that was never reached cannot be read as one that held.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

SOURCE = Path("crypto/smartcont/elector-code.fc")
BINARY = Path("build-p0/test/validator-auth-implementation/test-p0-elector-contract")

REFUSE = """  if (validator_auth_active() & (named_identity == 0)) {
    ;; an active chain has no use for a stake naming no identity: it could
    ;; never be selected, and leaving it in members would strand the stake
    cs.end_parse();
    return return_stake(s_addr, query_id, 7);
  }
"""
EXCLUDE = "      ifnot (auth_active & (named_identity == 0)) {\n"
FILL = "if (auth_active & val.slice_refs()) {"
REFUND = "    ifnot (rec.slice_refs()) {\n          credits~credit_to(refund_addr, refund_stake);\n        }"

# There is deliberately no mutation for `elector_bindings = new_dict()`. Making
# it conditional on activation was tried and broke nothing: an empty dictionary
# is a null cell in this language, so the sidecar check downstream cannot tell
# the two apart. What keeps an inactive election silent is the activation test
# in the fill, and that is what is mutated instead.
MUTATIONS = [
    ("stake-refused", "active-stake-without-identity-is-refused", REFUSE, "", []),
    # Removing the guard alone leaves its closing brace unbalanced, so the
    # replacement opens a block that is always taken: the record is selected.
    ("selection-excluded", "legacy-unbound-stake-is-excluded-and-refunded-after-activation", EXCLUDE,
     "      ifnot (false) {\n", []),
    # The half-fix: exclude the legacy record but never pay it back.
    ("legacy-refunded", "legacy-unbound-stake-is-excluded-and-refunded-after-activation", REFUND,
     "    ifnot (true) {\n          credits~credit_to(refund_addr, refund_stake);\n        }", []),
    ("binding-activation", "inactive-identity-bearing-election-sends-no-bindings", FILL,
     "if (val.slice_refs()) {", []),
    ("binding-emitted", "active-election-sends-one-binding-per-selected-member", FILL,
     "if (false & val.slice_refs()) {",
     ["legacy-unbound-stake-is-excluded-and-refunded-after-activation"]),
]


def contract(tree: str, workdir: str) -> str | None:
    fif, boc = f"{workdir}/elector.fif", f"{workdir}/elector.boc"
    if subprocess.run([f"{tree}/crypto/func", "-PS", "-o", fif, "crypto/smartcont/stdlib.fc", str(SOURCE)],
                      capture_output=True, text=True, check=False).returncode != 0:
        return None
    script = f"{workdir}/assemble.fif"
    Path(script).write_text(f'"Asm.fif" include\n"{fif}" include\n2 boc+>B "{boc}" B>file\n')
    if subprocess.run([f"{tree}/crypto/fift", "-I", "crypto/fift/lib", "-s", script],
                      capture_output=True, text=True, check=False).returncode != 0:
        return None
    return boc


def outcomes(boc: str) -> dict[str, bool]:
    result = subprocess.run([str(BINARY), boc], capture_output=True, text=True, check=False)
    return {line.split(" ", 1)[1].split(" (")[0]: line.startswith("CASE_PASS ")
            for line in result.stdout.splitlines() if line.startswith("CASE_")}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", default="build-p0")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    with tempfile.TemporaryDirectory() as work:
        boc = contract(args.build, work)
        if boc is None:
            print("BASELINE-CONTRACT-FAILED", file=sys.stderr)
            return 1
        inventory = outcomes(boc)
        if not inventory or not all(inventory.values()):
            print("BASELINE-NOT-PASSING", file=sys.stderr)
            return 1

        records, failures = [], 0
        try:
            for guard, case, before, after, companions in MUTATIONS:
                if original.count(before) != 1:
                    print(f"ANCHOR-NOT-UNIQUE {guard} ({original.count(before)})", file=sys.stderr)
                    failures += 1
                    continue
                changed = original.replace(before, after, 1)
                SOURCE.write_text(changed)
                reached = SOURCE.read_text() == changed
                mutated = contract(args.build, work)
                broke, complete = [], False
                if mutated is not None:
                    result = outcomes(mutated)
                    complete = set(result) == set(inventory)
                    broke = sorted(name for name, held in result.items() if not held)
                SOURCE.write_text(original)
                restored = contract(args.build, work) is not None and all(outcomes(boc).values())
                record = {"guard": guard, "case": case, "edit_reached_source": reached,
                          "compiled": mutated is not None, "every_case_reported": complete,
                          "cases_broken": broke, "declared_companions": companions,
                          "only_declared_cases_broke": case in broke and set(broke) <= {case, *companions},
                          "restored_baseline": restored, "source_unchanged": SOURCE.read_text() == original}
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
