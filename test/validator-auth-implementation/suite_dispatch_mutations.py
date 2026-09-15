"""Remove one part of suite dispatch at a time.

The property is that the suite a record declares selects the code that verifies
it. Before this existed the selection was implicit, and an implicit selection
cannot be removed to see what breaks -- which is why it survived.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

SOURCE = Path("validator/auth/crypto.cpp")
BINARY = Path("build-p0/test/validator-auth-implementation/test-p0-suite-dispatch")

MUTATIONS = [
    # The selection itself: admitting under one suite while recording another.
    # Nothing downstream can recover from that, and the first case is where it
    # shows, because a key tagged with the wrong suite verifies with the wrong
    # backend or with none.
    ("suite-recorded-at-admission", "each-suite-verifies-its-own-signature",
     '    return AdmittedKey(suite, std::get<c0::AdmittedKey>(std::move(key)));',
     '    return AdmittedKey(suite_mldsa44, std::get<c0::AdmittedKey>(std::move(key)));',
     ["a-signature-does-not-verify-under-another-suite"]),
    # Verification that reports success without doing any. The cross-suite case
    # is the one that notices, because it is the only one expecting a refusal
    # from a well-formed key.
    ("verification-actually-runs", "a-signature-does-not-verify-under-another-suite",
     '      case tos::pq::VerifyResult::invalid:\n      case tos::pq::VerifyResult::malformed_input:\n        return false;',
     '      case tos::pq::VerifyResult::invalid:\n      case tos::pq::VerifyResult::malformed_input:\n        return true;',
     []),
    ("post-quantum-key-length", "post-quantum-material-must-be-the-right-length",
     '    if (bytes.size() != tos::pq::mldsa44_public_key_bytes)\n      return Error{"public-key"};',
     '    if (bytes.size() < 1)\n      return Error{"public-key"};',
     ["material-offered-under-the-wrong-suite-is-refused"]),
    ("unknown-suite-refused", "a-suite-this-build-cannot-verify-is-refused-as-one",
     '  return Error{"unsupported-suite"};\n}\nResult<bool> AdmittedKey::verify(',
     '  return Error{"public-key"};\n}\nResult<bool> AdmittedKey::verify(',
     []),
    ("parameters-checked", "a-suite-this-build-cannot-verify-is-refused-as-one",
     '  if (parameters != parameters_default)\n    return Error{"unsupported-suite"};',
     '',
     []),
]


def invoke(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def build() -> bool:
    return invoke(["cmake", "--build", "build-p0", "--target", "test-p0-suite-dispatch", "-j48"]).returncode == 0


def run(material: list[str], selector: str | None = None) -> subprocess.CompletedProcess[str]:
    return invoke([str(BINARY), *material] + ([selector] if selector else []))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--message", required=True)
    parser.add_argument("--signature", required=True)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    material = [args.message, args.signature, args.public_key]

    original = SOURCE.read_text()
    baseline = run(material)
    if baseline.returncode != 0:
        print("BASELINE-NOT-PASSING", baseline.stderr[:200])
        return 1
    cases = [line.split()[1] for line in baseline.stdout.splitlines() if line.startswith("CASE_PASS")]

    records, failures = [], 0
    try:
        for guard, case, before, after, companions in MUTATIONS:
            if original.count(before) != 1:
                print(f"ANCHOR-NOT-UNIQUE {guard} ({original.count(before)})", file=sys.stderr)
                failures += 1
                continue
            SOURCE.write_text(original.replace(before, after, 1))
            reached = before not in SOURCE.read_text()
            compiled = build()
            named, isolated = False, False
            if compiled:
                # The named case is run on its own. Running the whole binary
                # would stop at the first failure, and a declared companion that
                # fails earlier would hide whether the named case fails at all
                # -- which it did, until the binary learned to run one case.
                alone = run(material, case)
                named = alone.returncode != 0 and case in (alone.stdout + alone.stderr)
                spared = [n for n in cases if n != case and n not in companions]
                isolated = all(run(material, n).returncode == 0 for n in spared)
            SOURCE.write_text(original)
            restored = build() and run(material).returncode == 0
            record = {"guard": guard, "case": case, "edit_reached_source": reached, "compiled": compiled,
                      "named_assertion_failed": named, "only_declared_cases_broke": isolated,
                      "declared_companions": companions, "restored_baseline": restored,
                      "source_unchanged": SOURCE.read_text() == original}
            records.append(record)
            print(json.dumps(record), flush=True)
            if not all(v for k, v in record.items() if k not in ("guard", "case", "declared_companions")):
                failures += 1
    finally:
        SOURCE.write_text(original)

    (args.out / "mutations.json").write_text(json.dumps(records, indent=1) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
