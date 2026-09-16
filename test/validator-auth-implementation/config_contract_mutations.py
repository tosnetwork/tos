"""Remove one part of the configuration account's persistence at a time.

The account carries the registry checkpoint its state is restored from, beside
the configuration parameter that holds the registry itself. Three separate
things keep that true: the load that reads it back, the store that writes it
forward, and the registry update that replaces it with the one for the state it
just staged. Each is removable on its own, so each is removed on its own.

The store is the one that hides. Every registry case starts from an account that
already has a checkpoint, so a store that dropped it would still leave a
registry update looking correct -- the damage appears one ordinary vote later,
in a block none of those cases reach.

Cases are run one at a time rather than as a suite, because this suite stops at
its first failure and a case that never ran cannot be told from one that held.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

SOURCE = Path("crypto/smartcont/config-code.fc")
BINARY = Path("build-p0/test/validator-auth-implementation/test-p0-config-contract")

LOAD = """  registry_checkpoint = null();
  if (cs.slice_refs()) {
    registry_checkpoint = cs~load_ref();
  }
"""
STORE = "    .store_checkpoint()\n"
STAGED = "    registry_checkpoint = vauth_registry_state();\n"

MUTATIONS = [
    ("checkpoint-stored", "a-registry-update-stores-the-staged-checkpoint", STORE, "", []),
    # Reading it back is what makes it survive an operation that does not touch
    # the registry; without it the account opens with nothing to carry forward,
    # and every case that restores one fails.
    ("checkpoint-loaded", "registry-c4-installs-parameter-46", LOAD,
     "  registry_checkpoint = null();\n  cs~load_ref();\n",
     ["registry-c4-replaces-old-parameter-46", "registry-first-checkpoint-installs-new-parameter",
      "registry-first-checkpoint-replaces-old-parameter"]),
    ("checkpoint-restaged", "a-registry-update-stores-the-staged-checkpoint", STAGED, "", []),
]


def contract(tree: str, workdir: str) -> str | None:
    fif, boc = f"{workdir}/config.fif", f"{workdir}/config.boc"
    if subprocess.run([f"{tree}/crypto/func", "-PS", "-o", fif, "crypto/smartcont/stdlib.fc", str(SOURCE)],
                      capture_output=True, text=True, check=False).returncode != 0:
        return None
    script = f"{workdir}/assemble.fif"
    Path(script).write_text(f'"Asm.fif" include\n"{fif}" include\n2 boc+>B "{boc}" B>file\n')
    if subprocess.run([f"{tree}/crypto/fift", "-I", "crypto/fift/lib", "-s", script],
                      capture_output=True, text=True, check=False).returncode != 0:
        return None
    return boc


def inventory(boc: str) -> list[str]:
    listed = subprocess.run([str(BINARY), boc, "--list"], capture_output=True, text=True, check=False)
    return [line.strip() for line in listed.stdout.splitlines() if line.strip()]


def outcomes(boc: str, cases: list[str]) -> dict[str, bool]:
    return {case: subprocess.run([str(BINARY), boc, case], capture_output=True, text=True,
                                 check=False).returncode == 0
            for case in cases}


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
        cases = inventory(boc)
        if not cases or not all(outcomes(boc, cases).values()):
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
                broke = []
                if mutated is not None:
                    broke = sorted(name for name, held in outcomes(mutated, cases).items() if not held)
                SOURCE.write_text(original)
                restored = contract(args.build, work) is not None and all(outcomes(boc, cases).values())
                record = {"guard": guard, "case": case, "edit_reached_source": reached,
                          "compiled": mutated is not None, "cases_run": len(cases), "cases_broken": broke,
                          "declared_companions": companions,
                          "only_declared_cases_broke": case in broke and set(broke) <= {case, *companions},
                          "restored_baseline": restored, "source_unchanged": SOURCE.read_text() == original}
                records.append(record)
                print(json.dumps(record), flush=True)
                if not all(record[key] for key in ("edit_reached_source", "compiled", "only_declared_cases_broke",
                                                   "restored_baseline", "source_unchanged")):
                    failures += 1
        finally:
            SOURCE.write_text(original)

    (args.out / "mutations.json").write_text(json.dumps(records, indent=1) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
