"""Run real crash-test sensitivity controls; restore production Store even on failure.

Run only in an isolated checkout with no concurrent compiler/editor. Compilation
must succeed before a failure in the expected runtime invariant can count.
"""

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    root = args.checkout.resolve()
    path = root / "tools/bonded-relayer/provider/src/store.rs"
    original = path.read_text()
    manifest = root / "tools/bonded-relayer/provider/Cargo.toml"
    args.out.mkdir(parents=True, exist_ok=False)
    rows = []
    command = [
        "cargo",
        "+1.97.1",
        "test",
        "--manifest-path",
        str(manifest),
        "--release",
        "--locked",
        "--test",
        "storage_crash_matrix",
        "--no-run",
        "--message-format=json",
    ]

    def build(name):
        result = subprocess.run(command, capture_output=True, timeout=1800, env=os.environ)
        (args.out / f"{name}-build.log").write_bytes(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(f"{name}: build failed, not runtime evidence")
        binaries = [
            x["executable"]
            for line in result.stdout.splitlines()
            if (x := json.loads(line)).get("reason") == "compiler-artifact"
            and x.get("executable")
            and x["target"]["name"] == "storage_crash_matrix"
        ]
        if len(binaries) != 1:
            raise RuntimeError("exact crash-test artifact required")
        return binaries[0]

    def run(name, case, expected=None):
        binary = build(name)
        result = subprocess.run(
            [binary] + (["--case", case] if case else []), capture_output=True, timeout=120
        )
        raw = result.stdout + result.stderr
        (args.out / f"{name}-runtime.log").write_bytes(raw)
        if expected:
            if not result.returncode or expected.encode() not in raw:
                raise RuntimeError(f"{name}: intended runtime invariant did not fail")
        elif result.returncode:
            raise RuntimeError(f"{name}: baseline/restoration failed")
        rows.append(
            dict(
                name=name,
                case=case,
                exit=result.returncode,
                expected=expected,
                sha256=hashlib.sha256(raw).hexdigest(),
                bytes=len(raw),
            )
        )

    mutations = [
        (
            "prepared-durability",
            "persist_prepared",
            "tx.commit()?;",
            "drop(tx);",
            "prepared.after_commit",
            "message durability",
        ),
        (
            "consume-atomicity",
            "consume",
            "let marked=tx.execute(",
            "tx.commit()?;\n        let tx = self.0.transaction_with_behavior(TransactionBehavior::Immediate)?;\n        let marked=tx.execute(",
            "consume.before_lease_sent",
            "permit/send-claim atomicity",
        ),
        (
            "refusal-atomicity",
            "retire_refused",
            'tx.execute("UPDATE permits SET used=1',
            'tx.execute_batch("COMMIT; BEGIN IMMEDIATE")?;\n            tx.execute("UPDATE permits SET used=1',
            "refusal.before_permits_retired",
            "retirement/permit atomicity",
        ),
        (
            "fee-durability",
            "import_fee",
            "tx.commit()?;",
            "drop(tx);",
            "fee.after_commit",
            "fee credit durability",
        ),
    ]
    try:
        run("baseline", None)
        for name, function, before, after, case, expected in mutations:
            start = original.index(f"    pub fn {function}(")
            end = original.find("\n    pub fn ", start + 1)
            if end < 0:
                end = original.index("\n}\n", start)
            fragment = original[start:end]
            if fragment.count(before) != 1:
                raise RuntimeError(f"{name}: mutation anchor changed")
            path.write_text(original[:start] + fragment.replace(before, after) + original[end:])
            run(name, case, expected)
            path.write_text(original)
        run("restored", None)
    finally:
        path.write_text(original)
    (args.out / "REPORT.json").write_text(
        json.dumps(
            dict(
                source_sha256=hashlib.sha256(original.encode()).hexdigest(),
                rows=rows,
                result="PASS",
            ),
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
