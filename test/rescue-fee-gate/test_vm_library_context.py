"""Run both library adapters; require VM witnesses and bounded preflight errors."""

import argparse
import json
import subprocess
from pathlib import Path

from vm_library_scenarios import fixtures


def run(binary, scenarios, libraries=None):
    command = [str(binary.resolve()), str(scenarios.resolve())]
    if libraries is not None:
        command.append(str(libraries.resolve()))
    return subprocess.run(command, capture_output=True, text=True, timeout=30)


def check(native, rust, output):
    assert not output.exists(), "library control output must be fresh"
    output.mkdir(parents=True)
    libraries, rows, expected = fixtures()
    scenarios = output / "scenarios.tsv"
    scenarios.write_text("".join("\t".join(row) + "\n" for row in rows))
    library_file = output / "libraries.boc"
    library_file.write_bytes(libraries.boc())
    results = []
    for name, binary in (("native", native), ("rust", rust)):
        baseline = run(binary, scenarios, library_file)
        assert baseline.returncode == 0 and baseline.stdout.endswith("\n"), baseline.stderr
        lines = [line.split("\t") for line in baseline.stdout.splitlines()]
        assert len(lines) == len(expected), "library context baseline population"
        for row, (case, wanted) in zip(lines, expected.items(), strict=True):
            assert row[:8] == [case, *wanted], (name, case, "library context baseline", row, wanted)
        disabled = run(binary, scenarios)
        assert disabled.returncode == 0, (name, "disabled context setup error", disabled.stderr)
        first = disabled.stdout.splitlines()[0].split("\t")
        assert first[:4] == [rows[0][0], "9", "194", "3"] and first[7] == "0", (
            name,
            "disabled library must reach missing-library VM error",
            first,
        )
        assert first[:8] != lines[0][:8], "library collection ignored by positive witness"
        results.append(dict(driver=name, control="disabled-context", vm_exit=9, gas=194))
        for label, size in (("empty", 0), ("exact", 1024 * 1024), ("over", 1024 * 1024 + 1)):
            path = output / (name + "-" + label)
            path.write_bytes(b"\0" * size)
            refused = run(binary, scenarios, path)
            assert refused.returncode != 0 and refused.stdout == "", (name, label, "preflight")
            witness = (
                "invalid library collection size"
                if label != "exact"
                else "invalid library collection BOC"
                if name == "native"
                else "unknown BOC_TAG"
            )
            assert witness in refused.stderr, (name, label, "wrong refusal", refused.stderr)
            results.append(dict(driver=name, control=label, witness=witness))
        restored = run(binary, scenarios, library_file)
        assert restored.returncode == 0 and restored.stdout == baseline.stdout, (
            name,
            "library context restoration",
        )
        (output / (name + ".tsv")).write_text(baseline.stdout)
    (output / "controls.json").write_text(json.dumps(results, indent=2) + "\n")
    print("PASS:10 authored effects per driver;8 context/bound controls;restored outputs identical")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    check(args.native, args.rust, args.output)


if __name__ == "__main__":
    main()
