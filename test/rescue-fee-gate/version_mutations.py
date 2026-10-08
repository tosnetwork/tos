"""Prove the native suite gate rejects early activation and delayed activation.

Usage: version_mutations.py <build-dir> <version-scenarios.tsv> <rust.tsv> <output-dir>
The Rust output must come from the unmodified version-16 build. Compiler failures
are not accepted as evidence. Source and executable are restored before returning.
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "crypto/vm/pqops.h"
COMPARE = Path(__file__).with_name("compare.py")


def main(build, scenarios, rust, output):
    build, scenarios, rust, output = map(
        lambda p: Path(p).resolve(), (build, scenarios, rust, output)
    )
    output.mkdir(parents=True, exist_ok=True)
    original = HEADER.read_text()
    anchor = "inline constexpr int pq_suite_min_version = 16;"
    if original.count(anchor) != 1:
        raise RuntimeError("native version anchor must occur exactly once")

    def run(label):
        with (output / f"{label}-build.log").open("w") as log:
            subprocess.run(
                ["cmake", "--build", str(build), "--target", "test-pq-suite-parity", "-j4"],
                check=True,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        results = output / f"{label}.tsv"
        with results.open("w") as stream:
            subprocess.run(
                [str(build / "crypto/pq/test-pq-suite-parity"), str(scenarios)],
                check=True,
                stdout=stream,
            )
        result = subprocess.run(
            [sys.executable, str(COMPARE), str(scenarios), str(results), str(rust)],
            capture_output=True,
            text=True,
        )
        (output / f"{label}.log").write_text(result.stdout + result.stderr)
        return result

    if run("baseline").returncode:
        raise RuntimeError("native baseline must pass before mutations")
    receipts = []
    try:
        for version, assertion in ((15, "version-15-suite-1"), (17, "version-16-suite-1")):
            HEADER.write_text(original.replace(anchor, anchor.replace("= 16;", f"= {version};")))
            result = run(f"gate-{version}")
            if (
                result.returncode == 0
                or "AssertionError:" not in result.stderr
                or assertion not in result.stderr
            ):
                raise RuntimeError(f"gate {version} did not fail its intended assertion")
            receipts.append({"gate": version, "caught": True, "assertion": assertion})
    finally:
        HEADER.write_text(original)
        if run("restored").returncode:
            raise RuntimeError("restored native baseline must pass")
    report = {"mutations": receipts, "restored_green": True}
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main(*sys.argv[1:])
