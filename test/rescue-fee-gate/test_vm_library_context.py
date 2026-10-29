"""Run both library adapters; require VM witnesses and bounded preflight errors."""

import argparse
import json
import subprocess
from pathlib import Path

from vm_library_scenarios import Cell, fixtures, make_dict


def run(binary, scenarios, libraries=None):
    command = [str(binary.resolve()), str(scenarios.resolve())]
    if libraries is not None:
        paths = [libraries] if isinstance(libraries, Path) else libraries
        command.extend(str(path.resolve()) for path in paths)
    return subprocess.run(command, capture_output=True, text=True, timeout=30)


def check(native, rust, output):
    assert not output.exists(), "library control output must be fresh"
    output.mkdir(parents=True)
    libraries, rows, expected = fixtures()
    scenarios = output / "scenarios.tsv"
    scenarios.write_text("".join("\t".join(row) + "\n" for row in rows))
    library_file = output / "libraries.boc"
    library_file.write_bytes(libraries.boc())
    target = Cell().raw(b"hello library")
    key = int.from_bytes(target.hash, "big")
    bad = {}
    for name, value in (
        ("wrong-hash", make_dict({key: Cell().ref(Cell().raw(b"wrong"))}, 256)),
        ("missing-ref", make_dict({key: Cell().uint(1, 1)}, 256)),
        ("malformed", Cell().uint(0, 1)),
    ):
        bad[name] = output / (name + ".boc")
        bad[name].write_bytes(value.boc())
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
        for label, contexts in (
            ("wrong-hash-fallback", [bad["wrong-hash"], library_file]),
            ("missing-ref-fallback", [bad["missing-ref"], library_file]),
            ("malformed-fallback", [bad["malformed"], library_file]),
            ("first-usable", [library_file, bad["wrong-hash"], bad["malformed"]]),
            ("four-collections", [*bad.values(), library_file]),
        ):
            resolved = run(binary, scenarios, contexts)
            assert resolved.returncode == 0 and resolved.stdout == baseline.stdout, (
                name,
                label,
                "library fallback mismatch",
                resolved.stdout,
                resolved.stderr,
            )
            (output / (name + "-" + label + ".tsv")).write_text(resolved.stdout)
            results.append(dict(driver=name, control=label, cases=len(expected)))
        cold = output / (name + "-cold.tsv")
        cold.write_text("\t".join(rows[0]) + "\n")
        absent = run(binary, cold, list(bad.values()))
        assert (
            absent.returncode == 0 and absent.stdout.splitlines()[0].split("\t")[:8] == first[:8]
        ), (name, "all collections unusable", absent.stdout, absent.stderr)
        results.append(dict(driver=name, control="all-unusable", vm_exit=9, gas=194))
        count = run(binary, scenarios, [library_file] * 5)
        assert count.returncode != 0 and count.stdout == "" and "at most 4" in count.stderr, (
            name,
            "collection count limit",
            count.stdout,
            count.stderr,
        )
        results.append(dict(driver=name, control="collection-count", maximum=4))
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
        aggregate = run(binary, scenarios, [library_file, output / (name + "-exact")])
        assert (
            aggregate.returncode != 0
            and aggregate.stdout == ""
            and "invalid library collection size" in aggregate.stderr
        ), (name, "aggregate byte budget", aggregate.stdout, aggregate.stderr)
        results.append(dict(driver=name, control="aggregate-budget", maximum=1024 * 1024))
        restored = run(binary, scenarios, library_file)
        assert restored.returncode == 0 and restored.stdout == baseline.stdout, (
            name,
            "library context restoration",
        )
        (output / (name + ".tsv")).write_text(baseline.stdout)
    (output / "controls.json").write_text(json.dumps(results, indent=2) + "\n")
    print(
        "PASS:10 authored effects per driver;",
        len(results),
        "context/fallback/bound controls;restored outputs identical",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    check(args.native, args.rust, args.output)


if __name__ == "__main__":
    main()
