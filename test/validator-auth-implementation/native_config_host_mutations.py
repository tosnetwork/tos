"""Compile native-config-host mutants and require isolated named failures.

A mutation counts only when it compiles, reaches the file, and then fails the
named assertion for the reason it was written for. A compilation failure is not
a kill, and a mutation that trips a different assertion proves nothing about the
guard it was aimed at.
"""
import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

SOURCE = Path("validator/auth/native-config-host.cpp")

# Each entry names the assertion it must break. Anchors are written against the
# source as the formatter leaves it.
MUTATIONS = [
    (
        # Settling only after the outcome is known. The copy that did the
        # reading is destroyed with its remainder inside it, so the prefix that
        # outlives the attempt would keep the old allowance and the next attempt
        # would read the registry from the same starting point again.
        "refused-work-not-settled",
        "host-refusal-spends-the-allowance",
        "guard-disable",
        "  auto settled = accepted_.settle_work(performed);\n"
        "  if (!settled.ok())\n"
        "    refuse_host(\"native work meter\");\n",
        "",
    ),
    (
        # The prefix cannot move on refusal by construction: apply_transaction is
        # const and returns a new block, so there is no in-place path to mutate.
        # What a guard does hold is that the refusal is a refusal at all, so that
        # is what this aims at. The prefix-stability assertion stays in the test
        # as a check on that structural property, and is recorded as structurally
        # held rather than mutation-covered.
        "refusal-not-refused",
        "host-refusal-throws",
        "guard-disable",
        "  if (!next.ok())\n"
        "    refuse_host(\"native update refused\");",
        "  if (!next.ok())\n"
        "    return accepted_.state().encode_cell().value();",
    ),
    (
        # The instruction is handed the evidence the contract received. Without
        # this the host reads that cell itself, under an assumption admission
        # does not share, and becomes a second authority on what the transaction
        # carried.
        "evidence-operand-unbound",
        "host-refuses-evidence-it-did-not-admit",
        "guard-disable",
        "  if (admitted_evidence_.is_null() || evidence->get_hash() != admitted_evidence_->get_hash())\n"
        "    refuse_host(\"native evidence operand\");",
        "  if (admitted_evidence_.is_null())\n"
        "    refuse_host(\"native evidence operand\");",
    ),
    (
        "operand-encoding-unchecked",
        "host-operand-encoding-refused",
        "guard-disable",
        "  auto raw_update = unpack_bytes(std::move(update));\n"
        "  if (!raw_update.ok())\n"
        "    refuse_host(\"native update encoding\");",
        "  auto raw_update = unpack_bytes(std::move(update));\n"
        "  if (!raw_update.ok())\n"
        "    return accepted_.state().encode_cell().value();",
    ),
    (
        "apply-returns-unstaged",
        "host-apply-returns-staged",
        "semantic-fault",
        "  auto encoded = next.value().state().encode_cell();\n"
        "  if (!encoded.ok())\n"
        "    refuse_host(\"native registry state\");",
        "  auto encoded = accepted_.state().encode_cell();\n"
        "  if (!encoded.ok())\n"
        "    refuse_host(\"native registry state\");",
    ),
]


def build(target: str) -> bool:
    return subprocess.run(
        ["cmake", "--build", "build-p0", "--target", target, "-j48"],
        capture_output=True, text=True, check=False,
    ).returncode == 0


def run(binary: Path, owner: Path, work: Path) -> subprocess.CompletedProcess:
    shutil.rmtree(work, ignore_errors=True)
    return subprocess.run(
        [str(binary), "verify", str(owner), str(work)],
        capture_output=True, text=True, check=False,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    binary = Path("build-p0/test/validator-auth-implementation/test-p0-native-config-host")
    original = SOURCE.read_text()
    backup = args.out / "native-config-host.orig"
    backup.write_text(original)

    baseline = run(binary, args.owner, args.out / "baseline")
    if baseline.returncode != 0:
        print("BASELINE-NOT-PASSING", baseline.stderr.strip()[:200])
        return 1

    records, failures = [], 0
    for guard, assertion, kind, before, after in MUTATIONS:
        if original.count(before) != 1:
            print(f"ANCHOR-NOT-UNIQUE {guard} ({original.count(before)})")
            failures += 1
            continue
        SOURCE.write_text(original.replace(before, after, 1))
        reached = after in SOURCE.read_text()
        compiled = build("test-p0-native-config-host")
        named = False
        if compiled:
            result = run(binary, args.owner, args.out / guard)
            named = result.returncode != 0 and assertion in (result.stderr + result.stdout)
        SOURCE.write_text(original)
        restored = build("test-p0-native-config-host") and run(binary, args.owner, args.out / f"{guard}-restored").returncode == 0
        record = {
            "guard": guard, "assertion": assertion, "kind": kind,
            "edit_reached_source": reached, "compiled": compiled,
            "named_assertion_failed": named, "restored_baseline": restored,
            "source_unchanged": SOURCE.read_text() == original,
        }
        records.append(record)
        print(json.dumps(record))
        if not (reached and compiled and named and restored and record["source_unchanged"]):
            failures += 1

    (args.out / "mutations.json").write_text(json.dumps(records, indent=1))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
