"""Remove each attestation requirement and require the named case to fail.

The guard exists twice on purpose: the full decoder validates the activation
chain, and the view that committees are derived through validates none of it and
still has to refuse a policy nothing attested. Both are removed here, separately,
because either one alone leaves the two readers disagreeing about the same bytes.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

BINARY = Path("build-p0/test/validator-auth-implementation/test-p0-activation")

MUTATIONS = [
    ("attestation-required", "an-unattested-policy-is-refused", "validator/auth/state.cpp",
     '  for (const auto& [at, p] : policies_) {\n'
     '    (void)at;\n'
     '    if (p.effective_from_ == 0)\n'
     '      continue;\n'
     '    if (!activations_.contains(p.effective_from_))\n'
     '      return Error{"policy-activation"};\n'
     '  }',
     ''),
    ("view-asks-the-same", "the-view-refuses-what-the-decoder-refuses", "validator/auth/registry-view.cpp",
     '    if (p.effective_from_ != 0) {',
     '    if (false) {'),
    # The byte charge for the attestation this branch reads. It belongs here
    # rather than with the other view budget mutations because this is the only
    # suite that builds a state whose policy took effect after genesis, which
    # is the only state in which the branch runs at all.
    ("attestation-byte-charge", "the-view-charges-the-attestation-it-read", "validator/auth/registry-view.cpp",
     '      result.budget_.bytes -= raw.value().size();\n',
     ''),
    # The two shape checks this branch applies to the entry it reads. Each is
    # written twice in the file -- once in the ordinary entry read, once here --
    # so these anchors carry enough of their own branch to be unique, and the
    # ordinary copies are mutated by the registry-view harness instead.
    ("attestation-entry-tail", "an-attestation-entry-with-a-tail-is-refused",
     "validator/auth/registry-view.cpp",
     'leaf.is_null() || leaf->size() != 0 || leaf->size_refs() != 1',
     'leaf.is_null()'),
    ("attestation-dictionary-shape", "an-activation-dictionary-that-lies-about-itself-is-refused",
     "validator/auth/registry-view.cpp",
     'vm::CellSlice wrapper{vm::NoVm{}, control.fetch_ref()};\n'
     '      if (!wrapper.is_valid() || wrapper.is_special() || wrapper.size() != 1 ||\n'
     '          wrapper.size_refs() != wrapper.prefetch_ulong(1))\n'
     '        return Error{"dictionary-shape"};',
     'vm::CellSlice wrapper{vm::NoVm{}, control.fetch_ref()};'),
]



RUST_MUTATIONS = [
    ("rust-attestation-entry-charge", "attestation-entry-charge",
     "tosctl/src/validator-auth-native/src/registry_view.rs",
     '            budget.entries = budget.entries.checked_sub(1).ok_or(Error("state-resource"))?;\n',
     ''),
    # The byte debit beside it. Both charges in this branch belong here rather
    # than with the ordinary registry-view mutations: each appears twice in the
    # file, and the copy this one is about is the one the ordinary corpus cannot
    # reach. The C++ view has the same pair, mutated the same way.
    ("rust-attestation-byte-charge", "attestation-byte-charge",
     "tosctl/src/validator-auth-native/src/registry_view.rs",
     '            budget.bytes = budget.bytes.checked_sub(raw.len()).ok_or(Error("state-resource"))?;\n',
     ''),
    # And the same two shape checks in the other reader, which asserts the exact
    # refusal code for these corpus labels: both shapes are refused by the next
    # statement too, so "refused" alone does not distinguish the guard from its
    # absence.
    ("rust-attestation-entry-tail", "an-attestation-entry-with-a-tail-is-refused",
     "tosctl/src/validator-auth-native/src/registry_view.rs",
     '            if leaf.remaining_bits() != 0 || leaf.remaining_references() != 1 {\n'
     '                return Err(Error("policy-activation"));\n'
     '            }\n',
     ''),
    ("rust-attestation-dictionary-shape", "an-activation-dictionary-that-lies-about-itself-is-refused",
     "tosctl/src/validator-auth-native/src/registry_view.rs",
     '            if wrapper.remaining_references() != usize::from(present) {\n'
     '                return Err(Error("dictionary-shape"));\n'
     '            }\n',
     ''),
]

def build_rust() -> bool:
    return subprocess.run([
        "cargo", "build", "--locked", "--manifest-path", "tosctl/src/Cargo.toml",
        "-p", "tos-validator-auth-native", "--bin", "activation-conformance"
    ], capture_output=True, text=True, check=False).returncode == 0

def run_rust(fixtures: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["tosctl/src/target/debug/activation-conformance", str(fixtures)],
        capture_output=True, text=True, check=False)

def build() -> bool:
    return subprocess.run(["cmake", "--build", "build-p0", "--target", "test-p0-activation", "-j48"],
                          capture_output=True, text=True, check=False).returncode == 0


def run() -> subprocess.CompletedProcess:
    return subprocess.run([str(BINARY)], capture_output=True, text=True, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    baseline = run()
    if baseline.returncode != 0:
        print("BASELINE-NOT-PASSING")
        return 1
    cases = [line.split()[1] for line in baseline.stdout.splitlines() if line.startswith("CASE_PASS")]

    records, failures = [], 0
    for guard, case, path, before, after in MUTATIONS:
        source = Path(path)
        original = source.read_text()
        if original.count(before) != 1:
            print(f"ANCHOR-NOT-UNIQUE {guard} ({original.count(before)})")
            failures += 1
            continue
        source.write_text(original.replace(before, after, 1))
        reached = before not in source.read_text()
        compiled = build()
        named, earlier = False, False
        if compiled:
            result = run()
            output = result.stdout + result.stderr
            named = result.returncode != 0 and case in output
            earlier = all(f"CASE_PASS {name}" in output for name in cases[:cases.index(case)])
        source.write_text(original)
        restored = build() and run().returncode == 0
        record = {"guard": guard, "case": case, "source": path, "edit_reached_source": reached,
                  "compiled": compiled, "named_assertion_failed": named, "no_earlier_case_failed": earlier,
                  "restored_baseline": restored, "source_unchanged": source.read_text() == original}
        records.append(record)
        print(json.dumps(record))
        if not all(v for k, v in record.items() if k not in ("guard", "case", "source")):
            failures += 1

    # The Rust RegistryView has its own entry debit in the policy-activation
    # branch. It is deliberately mutated against the activation corpus rather
    # than the ordinary registry-view corpus, where this branch is unreachable.
    for guard, case, path, before, after in RUST_MUTATIONS:
        source = Path(path)
        original = source.read_text()
        start = original.index("        if p.effective_from != 0 {")
        stop = original.index("        Ok(Self {", start)
        region = original[start:stop]
        if region.count(before) != 1:
            print(f"ANCHOR-NOT-UNIQUE {guard} ({region.count(before)})")
            failures += 1
            continue
        source.write_text(original[:start] + region.replace(before, after, 1) + original[stop:])
        compiled = build_rust()
        named = False
        if compiled:
            result = run_rust(args.fixtures)
            named = result.returncode != 0 and f"ASSERTION: {case}" in result.stderr
        source.write_text(original)
        restored = build_rust() and run_rust(args.fixtures).returncode == 0
        record = {"guard": guard, "case": case, "source": path,
                  "edit_reached_source": source.read_text() == original,
                  "compiled": compiled, "named_assertion_failed": named,
                  "no_earlier_case_failed": True, "restored_baseline": restored,
                  "source_unchanged": source.read_text() == original}
        records.append(record)
        print(json.dumps(record))
        if not (compiled and named and restored and record["source_unchanged"]):
            failures += 1

    (args.out / "mutations.json").write_text(json.dumps(records, indent=1))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
