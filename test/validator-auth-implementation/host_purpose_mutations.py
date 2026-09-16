"""Make a purpose-specific host implement an operation it must not.

The privileged surface is one interface with three operations, and no
transaction legitimately performs all three. The binding host is built for an
internal elector message and implements only the binding; the state host is
built for a tick-tock that carries no message at all and implements only
reading the state. A contract reaching either path must not be able to reach
the operations that path has no inputs for.

Each refusal is removed on its own, because a host that refused everything
would satisfy every refusal case for the wrong reason -- which is why each host
also has a case proving the one operation it does implement is reached.

The anchors are scoped to one function each: the refusal is written the same way
in all of them, and a mutation that could match any would not say which it
removed.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

BINDING = Path("validator/auth/native-election-binding-host.cpp")
STATE = Path("validator/auth/native-config-state-host.cpp")
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

    originals = {BINDING: BINDING.read_text(), STATE: STATE.read_text()}
    mutations = [
        (BINDING, "state-refused", "election-binding-host-refuses-state",
         scoped(originals[BINDING], "td::Ref<vm::Cell> NativeElectionBindingHost::checkpoint("),
         REFUSAL, "  return {};", []),
        (BINDING, "apply-refused", "election-binding-host-refuses-apply",
         scoped(originals[BINDING], "td::Ref<vm::Cell> NativeElectionBindingHost::apply("),
         REFUSAL, "  return {};", []),
        # The state host's two refusals, removed on their own for the same
        # reason: a host that refused everything would satisfy both cases
        # without implementing the one operation it exists for.
        (STATE, "state-host-apply-refused", "config-state-host-refuses-apply",
         scoped(originals[STATE], "td::Ref<vm::Cell> NativeConfigStateHost::apply("),
         REFUSAL, "  return {};", []),
        (STATE, "state-host-bind-refused", "config-state-host-refuses-bind",
         scoped(originals[STATE], "td::Ref<vm::Cell> NativeConfigStateHost::bind("),
         REFUSAL, "  return {};", []),
        # Settling the meter only after the outcome is known: the shape the
        # binding path had, where every refusal read the registry for free and
        # the next attempt began from the same allowance.
        (BINDING, "work-survives-refusal", "a-refused-binding-still-charges",
         scoped(originals[BINDING], "td::Ref<vm::Cell> NativeElectionBindingHost::bind("),
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
        for source, guard, case, body, before, after, companions in mutations:
            original = originals[source]
            assert original.count(body) == 1, guard
            assert body.count(before) == 1, (guard, "anchor")
            changed = original.replace(body, body.replace(before, after), 1)
            source.write_text(changed)
            reached = source.read_text() == changed
            compiled = build()
            broke, complete = [], False
            if compiled:
                result = outcomes()
                complete = set(result) == set(inventory)
                broke = sorted(name for name, held in result.items() if not held)
            source.write_text(original)
            restored = build() and all(outcomes().values())
            record = {"guard": guard, "case": case, "edit_reached_source": reached, "compiled": compiled,
                      "every_case_reported": complete, "cases_broken": broke,
                      "declared_companions": companions,
                      "only_declared_cases_broke": case in broke and set(broke) <= {case, *companions}, "restored_baseline": restored,
                      "source": str(source),
                      "source_unchanged": source.read_text() == original}
            records.append(record)
            print(json.dumps(record), flush=True)
            if not all(record[key] for key in ("edit_reached_source", "compiled", "every_case_reported",
                                               "only_declared_cases_broke", "restored_baseline", "source_unchanged")):
                failures += 1
    finally:
        for source, text in originals.items():
            source.write_text(text)

    (args.out / "mutations.json").write_text(json.dumps(records, indent=1) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
