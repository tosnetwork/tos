"""Delete native retirement guards and require specific config-transition tests to fail.

Run without another build/editor modifying auth-policy.cpp. Original source is
restored in finally; compile errors are never counted as mutation kills.
"""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--admission-only", action="store_true")
    args = parser.parse_args()
    args.build = args.build.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    source = ROOT / "crypto/block/auth-policy.cpp"
    mutations = [
        (
            "retired",
            "(next.retired & previous.retired) != previous.retired ||",
            "",
            "Test_AuthPolicy_absorbing_retirement_and_sequence",
        ),
        (
            "deadline",
            "(previous.deadline != 0 && (next.deadline == 0 || next.deadline > previous.deadline))",
            "false",
            "Test_AuthPolicy_deadlines_cannot_disappear_or_move_later",
        ),
        (
            "membership",
            "if (value.not_null()) {",
            "if (false) {",
            "Test_AuthPolicy_mandatory_version_and_membership",
        ),
    ]
    if args.admission_only:
        source = ROOT / "validator/auth-policy-admission.h"
        target = "Test_AuthPolicy_trusted_state_admission_preserves_errors_and_retirement"
        mutations = [
            ("skip_previous", "if (!has_previous)", "if (true)", target),
            (
                "candidate_lookup",
                "  TRY_RESULT(next, std::move(candidate));",
                "  if (candidate.is_error()) { return td::Status::OK(); }\n  TRY_RESULT(next, std::move(candidate));",
                target,
            ),
            (
                "previous_lookup",
                "  TRY_RESULT(old, std::move(previous));",
                "  if (previous.is_error()) { return td::Status::OK(); }\n  TRY_RESULT(old, std::move(previous));",
                target,
            ),
        ]
    original = source.read_bytes()
    results = {}

    def build(name):
        with (args.output / (name + "-build.log")).open("w") as log:
            subprocess.run(
                ["cmake", "--build", str(args.build), "--target", "test-config-transition", "-j4"],
                cwd=ROOT,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=True,
            )

    def run(name):
        result = subprocess.run(
            [str(args.build / "test-config-transition")], cwd=ROOT, capture_output=True
        )
        output = result.stdout + result.stderr
        (args.output / (name + ".log")).write_bytes(output)
        return result.returncode, output.decode(errors="replace")

    try:
        for name, old, new, test in mutations:
            text = original.decode()
            assert text.count(old) == 1
            source.write_text(text.replace(old, new))
            build(name)
            status, output = run(name)
            assert (
                status != 0
                and re.findall(r"Running test (\w+)", output)[-1] == test
                and "Expectation failed:" in output
            ), output[-4000:]
            results[name] = {
                "exit": status,
                "target_test": test,
                "output_sha256": hashlib.sha256(
                    (args.output / (name + ".log")).read_bytes()
                ).hexdigest(),
            }
    finally:
        source.write_bytes(original)
        build("restored")
        status, output = run("restored")
        assert status == 0, output[-4000:]
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
