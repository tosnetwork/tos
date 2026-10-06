"""Require early/late Falcon gates in each VM to fail the boundary test.

Run exclusively: this runner temporarily changes and rebuilds VM sources.
"""

import argparse
import json
import subprocess
import sys
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

    def run(command, label):
        with (out / (label + ".log")).open("w") as stream:
            return subprocess.run(
                list(map(str, command)), cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT
            ).returncode

    def check(label):
        return run(
            [
                sys.executable,
                ROOT / "test/pq-falcon512/version_boundary.py",
                "--build",
                args.build.resolve(),
                "--rust-examples",
                args.rust_examples.resolve(),
                "--out",
                out / label,
            ],
            label,
        )

    if check("baseline"):
        raise RuntimeError("baseline must pass before mutating")
    controls = []
    cases = [
        (
            "cpp",
            "crypto/vm/pqops.h",
            "pq_falcon512_min_version = 19",
            [
                "cmake",
                "--build",
                args.build.resolve(),
                "--target",
                "test-pq-falcon512-parity",
                "test-pq-suite-parity",
                "-j2",
            ],
        ),
        (
            "rust",
            "tosctl/src/vm/src/executor/pq.rs",
            "FALCON512_MIN_VERSION: u32 = 19",
            [
                "cargo",
                "build",
                "--manifest-path",
                "tosctl/src/Cargo.toml",
                "--locked",
                "-p",
                "tos_vm",
                "--example",
                "falcon-parity",
                "--example",
                "suite-parity",
                "-j1",
            ],
        ),
    ]
    for vm, name, anchor, build in cases:
        path = ROOT / name
        original = path.read_text()
        if original.count(anchor) != 1:
            raise RuntimeError("mutation anchor must occur exactly once")
        for gate in (18, 20):
            label = f"{vm}-gate-{gate}"
            try:
                path.write_text(original.replace(anchor, anchor.replace("19", str(gate))))
                if run(build, label + "-build"):
                    raise RuntimeError("mutation did not compile")
                code = check(label)
                report = json.loads((out / label / "result.json").read_text())
                boundary = 18 if gate == 18 else 19
                for entry in ("dedicated", "generic"):
                    if not any(
                        item.get("vm") == vm
                        and item.get("entry") == entry
                        and item.get("expected", [None])[0] == f"{entry}-{boundary}-s2-valid"
                        for item in report["failures"]
                    ):
                        raise RuntimeError("missing targeted boundary failure")
                if code != 1:
                    raise RuntimeError("mutation must produce a semantic test failure")
                controls.append(dict(vm=vm, gate=gate, exit=code, both_entries_detected=True))
            finally:
                path.write_text(original)
                if run(build, label + "-restored-build"):
                    raise RuntimeError("restored build failed")
            if check(label + "-restored"):
                raise RuntimeError("restored baseline failed")
    report = dict(passed=True, controls=controls, restored_green=True)
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
