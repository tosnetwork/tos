"""Require migration preflight tests to fail when their guards are removed."""

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()
    source = ROOT / "tools/falcon/provider.py"
    original = source.read_text()
    command = [
        sys.executable,
        str(ROOT / "test/falcon-auth/test_wallet.py"),
        "--library",
        str(args.library.resolve()),
        "--artifacts",
        str(args.artifacts.resolve()),
    ]

    def run():
        return subprocess.run(command, cwd=ROOT, text=True, capture_output=True)

    if run().returncode:
        raise RuntimeError("migration preflight baseline failed")
    reports = []
    for name, guard in [
        ("deployed-destination", 'if destination.status != "active":'),
        (
            "factor-confirmation",
            "if (old_profile != PROFILE or auth.mode != target_mode) and confirm_security_change is not True:",
        ),
    ]:
        if original.count(guard) != 1:
            raise ValueError("missing or ambiguous preflight mutation target")
        mutated = original.replace(guard, "if False:")
        # Syntax errors and import errors cannot count as a killed Python guard.
        compile(mutated, str(source), "exec")
        try:
            source.write_text(mutated)
            result = run()
            killed = (
                result.returncode != 0
                and "AssertionError:" in result.stderr
                and "test_cutover_requires_new_key_backup_and_explicit_factor_choice"
                in result.stderr
            )
            if not killed:
                raise RuntimeError("preflight mutation did not reach its target assertion")
            reports.append(
                dict(
                    guard=name,
                    compiled=True,
                    killed=True,
                    assertion=next(
                        line for line in result.stderr.splitlines() if "AssertionError:" in line
                    ),
                )
            )
        finally:
            source.write_text(original)
        if run().returncode:
            raise RuntimeError("restored migration preflight baseline failed")
    (args.artifacts / "provider-mutations.json").write_text(json.dumps(reports, indent=2) + "\n")
    print(
        "PASS: two preflight guard mutations reached failing assertions; restored baselines green"
    )


if __name__ == "__main__":
    main()
