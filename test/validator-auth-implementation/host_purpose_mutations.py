"""Make the binding host implement an operation it must not.

The privileged surface is one interface with three operations. This host is
built for an internal elector message and implements only the binding; a
contract reaching it through that path must not be able to read a registry
checkpoint or apply an update. Each refusal is removed on its own, because a
host that refused everything would satisfy both cases for the wrong reason.

The anchors are scoped to one function each: the refusal is written the same way
in both, and a mutation that could match either would not say which it removed.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

SOURCE = Path("validator/auth/native-election-binding-host.cpp")
BINARY = Path("build-p0/test/validator-auth-implementation/test-p0-host-purpose")
REFUSAL = '  refuse_instruction("P0 native transaction context required");'
SETTLE = ("  work_remaining_ = registry.value().remaining();\n"
          "  charge(as_gas(consumed(before, work_remaining_, gas_per_entry_, gas_per_byte_)));\n")
REFUSE = '  if (!bound.ok())\n    refuse_host("native binding refused");\n'



def scoped(text: str, signature: str) -> str:
    start = text.index(signature)
    return text[start:text.index("\n}\n", start)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    mutations = [
        ("state-refused", "election-binding-host-refuses-state",
         scoped(original, "td::Ref<vm::Cell> NativeElectionBindingHost::checkpoint("), REFUSAL, "  return {};", []),
        ("apply-refused", "election-binding-host-refuses-apply",
         scoped(original, "td::Ref<vm::Cell> NativeElectionBindingHost::apply("), REFUSAL, "  return {};", []),
        # Settling the meter only after the outcome is known: the shape the
        # binding path had, where every refusal read the registry for free and
        # the next attempt began from the same allowance.
        ("work-survives-refusal", "a-refused-binding-still-charges",
         scoped(original, "td::Ref<vm::Cell> NativeElectionBindingHost::bind("),
         SETTLE + "\n" + REFUSE,
         REFUSE + "\n" + SETTLE,
         ["repeated-refusals-exhaust-the-allowance"]),
    ]

    def build() -> bool:
        return subprocess.run(["cmake", "--build", "build-p0", "--target", "test-p0-host-purpose", "-j48"],
                              capture_output=True, text=True, check=False).returncode == 0

    def outcomes() -> dict[str, bool]:
        result = subprocess.run([str(BINARY)], capture_output=True, text=True, check=False)
        return {line.split(" ", 1)[1]: line.startswith("CASE_PASS ")
                for line in result.stdout.splitlines() if line.startswith("CASE_")}

    if not build():
        print("BASELINE-BUILD-FAILED", file=sys.stderr)
        return 1
    inventory = outcomes()
    if not inventory or not all(inventory.values()):
        print("BASELINE-NOT-PASSING", file=sys.stderr)
        return 1

    records, failures = [], 0
    try:
        for guard, case, body, before, after, companions in mutations:
            assert original.count(body) == 1, guard
            assert body.count(before) == 1, (guard, "anchor")
            changed = original.replace(body, body.replace(before, after), 1)
            SOURCE.write_text(changed)
            reached = SOURCE.read_text() == changed
            compiled = build()
            broke, complete = [], False
            if compiled:
                result = outcomes()
                complete = set(result) == set(inventory)
                broke = sorted(name for name, held in result.items() if not held)
            SOURCE.write_text(original)
            restored = build() and all(outcomes().values())
            record = {"guard": guard, "case": case, "edit_reached_source": reached, "compiled": compiled,
                      "every_case_reported": complete, "cases_broken": broke,
                      "declared_companions": companions,
                      "only_declared_cases_broke": case in broke and set(broke) <= {case, *companions}, "restored_baseline": restored,
                      "source_unchanged": SOURCE.read_text() == original}
            records.append(record)
            print(json.dumps(record), flush=True)
            if not all(record[key] for key in ("edit_reached_source", "compiled", "every_case_reported",
                                               "only_declared_cases_broke", "restored_baseline", "source_unchanged")):
                failures += 1
    finally:
        SOURCE.write_text(original)

    (args.out / "mutations.json").write_text(json.dumps(records, indent=1) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
