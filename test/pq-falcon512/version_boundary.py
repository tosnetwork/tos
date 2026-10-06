"""Execute both Falcon entry points across the frozen version-19 boundary.

The gate expectations are independent of production constants. Frozen public
signatures exercise real verification after activation, including an invalid
signature control. This is an opcode test, not release-genesis acceptance.
"""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--rust-examples", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    frozen = ROOT / "test/rescue-fee-gate/suite-scenarios.tsv"
    fixtures = {
        row[0]: row
        for row in (line.split("\t") for line in frozen.read_text().splitlines())
        if row[0] in ("s2-valid", "s2-bitflip")
    }
    if set(fixtures) != {"s2-valid", "s2-bitflip"}:
        raise RuntimeError("missing independent valid/invalid Falcon fixtures")
    failures = []
    counts = {}
    for entry in ("dedicated", "generic"):
        scenarios = []
        expected = []
        for version in range(21):
            for label, fixture in sorted(fixtures.items()):
                name = f"{entry}-{version}-{label}"
                message, context, signature, key = fixture[5:9]
                verdict = -1 if label == "s2-valid" else 0
                code = 0 if version >= 19 else 6 if entry == "dedicated" or version < 16 else 5
                expected.append((name, code, verdict if code == 0 else 99))
                if entry == "dedicated":
                    row = [name, version, 1000000, 0, 1, "?", message, "skip", signature, key]
                else:
                    row = [name, version, 1000000, "?", "int:2", message, context, signature, key]
                scenarios.append("\t".join(map(str, row)))
        inputs = out / f"{entry}-scenarios.tsv"
        inputs.write_text("\n".join(scenarios) + "\n")
        native = "test-pq-falcon512-parity" if entry == "dedicated" else "test-pq-suite-parity"
        rust = "falcon-parity" if entry == "dedicated" else "suite-parity"
        outputs = []
        for vm, binary in (
            ("cpp", args.build.resolve() / "crypto/pq" / native),
            ("rust", args.rust_examples.resolve() / rust),
        ):
            result = subprocess.run([str(binary), str(inputs)], capture_output=True, text=True)
            (out / f"{entry}-{vm}.tsv").write_text(result.stdout)
            (out / f"{entry}-{vm}.stderr").write_text(result.stderr)
            if result.returncode:
                raise RuntimeError(f"{entry}/{vm}: driver failed: {result.returncode}")
            rows = [line.split("\t") for line in result.stdout.splitlines()]
            if len(rows) != len(expected) or any(
                len(row) != (7 if entry == "dedicated" else 4) for row in rows
            ):
                raise RuntimeError(f"{entry}/{vm}: incomplete execution evidence")
            for row, want in zip(rows, expected):
                actual = (row[0], int(row[1]), int(row[3]))
                if actual != want:
                    failures.append(dict(entry=entry, vm=vm, expected=want, actual=actual))
                if int(row[2]) <= 0:
                    raise RuntimeError("missing gas charge")
                if entry == "dedicated" and int(row[4]) != (1 if want[1] == 0 else 0):
                    failures.append(dict(entry=entry, vm=vm, case=row[0], error="commit mismatch"))
            outputs.append(["\t".join(row).lower() for row in rows])
        if outputs[0] != outputs[1]:
            failures.append(dict(entry=entry, error="cross-VM execution divergence"))
        counts[entry] = len(expected)
    report = dict(passed=not failures, cases_per_vm=counts, failures=failures)
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
