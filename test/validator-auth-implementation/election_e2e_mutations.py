"""Break one seam of the election join at a time.

Every piece of this path has a suite that passes against fixtures the piece
beside it does not produce. The join is the only place a seam between two of
them can fail, so the mutations here are seam mutations: remove the authority
the contract needs, remove the contract's call to the instruction, and have the
instruction hand back the set that arrived instead of the bound one.

Each must kill only the cases that actually depend on it. The contract is
recompiled the way the suite compiles it, so a contract mutation is measured
through the same bytes the suite runs.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

CONTRACT = Path("crypto/smartcont/config-code.fc")
HOST = Path("validator/auth/native-election-binding-host.cpp")
ASSEMBLER = Path("validator/auth/native-collation-authority.cpp")

BIND_CALL = "        vset = vauth_bind_validators(vset, bindings);\n"
# The host keeps the bound set in a member before answering with it, so the
# seam is the binder's own result rather than the return statement. Anchoring
# on the call also means the arrived set is still available to hand back: by
# the return it has been moved into the binder.
BOUND_RETURN = ("  auto bound = bind_elected_validators(std::move(elected), declared.value(), "
                "registry.value(), coordinate_);")
AUTHORITY = "  return NativeElectionBindingTransaction::open(\n"

MUTATIONS = [
    # The contract stops asking. Nothing binds, so the set installed is the one
    # that arrived.
    ("contract-calls-the-instruction", "the-installed-set-is-the-bound-one-not-the-one-that-arrived",
     CONTRACT, BIND_CALL, "",
     ["the-contract-reaches-the-instruction-through-the-authority"]),
    # The instruction answers with what it was handed. Every case that compares
    # the bound set against the one that arrived fails.
    ("instruction-returns-the-bound-set", "the-bound-set-is-not-the-set-that-arrived",
     HOST, BOUND_RETURN,
     "  auto arrived = elected;\n" + BOUND_RETURN + "\n  if (bound.ok())\n    bound = arrived;",
     ["the-installed-set-is-the-bound-one-not-the-one-that-arrived"]),
    # No authority is assembled for the message the elector actually sent.
    ("assembler-opens-a-transaction", "the-message-the-elector-sent-assembles-a-binding-authority",
     ASSEMBLER, AUTHORITY, '  return Error{"election-binding-unavailable"};\n  return NativeElectionBindingTransaction::open(\n',
     ["the-authority-binds-the-set-the-election-produced", "the-bound-set-keeps-its-shape",
      "the-bound-set-is-not-the-set-that-arrived",
      "a-second-assembly-of-the-same-message-binds-the-same-bytes",
      "the-contract-reaches-the-instruction-through-the-authority",
      "the-contract-installs-the-bound-set",
      "the-installed-set-is-the-bound-one-not-the-one-that-arrived"]),
]


def build(tree: str) -> bool:
    return subprocess.run(["cmake", "--build", tree, "--target", "test-p0-election-e2e", "-j48"],
                          capture_output=True, text=True, check=False).returncode == 0


def contracts(tree: str, workdir: str) -> tuple[str, str] | None:
    out = []
    for name in ("elector", "config"):
        fif, boc = f"{workdir}/{name}.fif", f"{workdir}/{name}.boc"
        if subprocess.run([f"{tree}/crypto/func", "-PS", "-o", fif, "crypto/smartcont/stdlib.fc",
                           f"crypto/smartcont/{name}-code.fc"], capture_output=True, text=True,
                          check=False).returncode != 0:
            return None
        script = f"{workdir}/{name}.assemble.fif"
        Path(script).write_text(f'"Asm.fif" include\n"{fif}" include\n2 boc+>B "{boc}" B>file\n')
        if subprocess.run([f"{tree}/crypto/fift", "-I", "crypto/fift/lib", "-s", script],
                          capture_output=True, text=True, check=False).returncode != 0:
            return None
        out.append(boc)
    return out[0], out[1]


def outcomes(tree: str, owner: str, built: tuple[str, str]) -> dict[str, bool]:
    result = subprocess.run([f"{tree}/test/validator-auth-implementation/test-p0-election-e2e",
                             built[0], owner, built[1]], capture_output=True, text=True, check=False)
    return {line.split(" ", 1)[1]: line.startswith("CASE_PASS ")
            for line in result.stdout.splitlines() if line.startswith("CASE_")}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", default="build-p0")
    parser.add_argument("--owner", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    pristine = {path: path.read_text() for path in {CONTRACT, HOST, ASSEMBLER}}
    with tempfile.TemporaryDirectory() as work:
        if not build(args.build):
            print("BASELINE-BUILD-FAILED", file=sys.stderr)
            return 1
        built = contracts(args.build, work)
        if built is None:
            print("BASELINE-CONTRACT-FAILED", file=sys.stderr)
            return 1
        inventory = outcomes(args.build, args.owner, built)
        if not inventory or not all(inventory.values()):
            print("BASELINE-NOT-PASSING", file=sys.stderr)
            return 1

        records, failures = [], 0
        try:
            for guard, case, source, before, after, companions in MUTATIONS:
                original = pristine[source]
                if original.count(before) != 1:
                    print(f"ANCHOR-NOT-UNIQUE {guard} ({original.count(before)})", file=sys.stderr)
                    failures += 1
                    continue
                changed = original.replace(before, after, 1)
                source.write_text(changed)
                reached = source.read_text() == changed
                compiled = build(args.build)
                mutated = contracts(args.build, work) if compiled else None
                broke, complete = [], False
                if mutated is not None:
                    result = outcomes(args.build, args.owner, mutated)
                    complete = set(result) == set(inventory)
                    broke = sorted(name for name, held in result.items() if not held)
                source.write_text(original)
                # Recompiled, because a contract mutation writes its bytes to the
                # same path the baseline occupies: checking the restore against
                # a stale file would report the mutation as still in place.
                rebuilt = contracts(args.build, work) if build(args.build) else None
                restored = rebuilt is not None and all(outcomes(args.build, args.owner, rebuilt).values())
                record = {"guard": guard, "case": case, "source": str(source), "edit_reached_source": reached,
                          "compiled": compiled and mutated is not None, "every_case_reported": complete,
                          "cases_broken": broke, "declared_companions": companions,
                          "only_declared_cases_broke": case in broke and set(broke) <= {case, *companions},
                          "restored_baseline": restored, "source_unchanged": source.read_text() == original}
                records.append(record)
                print(json.dumps(record), flush=True)
                if not all(record[key] for key in ("edit_reached_source", "compiled", "every_case_reported",
                                                   "only_declared_cases_broke", "restored_baseline",
                                                   "source_unchanged")):
                    failures += 1
        finally:
            for path, text in pristine.items():
                path.write_text(text)

    (args.out / "mutations.json").write_text(json.dumps(records, indent=1) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
