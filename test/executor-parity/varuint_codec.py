"""Authored unsigned-integer boundaries, followed by independent native/Rust execution."""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "test/auth-extensions"), str(ROOT / "test/rel02")]
from cells import Cell  # noqa: E402
from run_rust import binary_hash, execute  # noqa: E402

MAX_OUTPUT = 1024 * 1024


def cases():
    result = []

    def add(name, op, n, data, accepted, skip="-", value=None):
        row = dict(name=name, op=op, n=n, data=data or "-")
        if accepted:
            length = (value.bit_length() + 7) // 8
            width = (n - 1).bit_length()
            bits = f"{length:0{width}b}" + (f"{value:0{length * 8}b}" if length else "")
            output = ["1", str(value), Cell(bits=bits).hash.hex(), str(skip)]
        else:
            output = ["0", "-", "-", str(skip)]
        row["expected"] = [name, *output]
        result.append(row)

    # TL-B len < n; validated nonempty values have a nonzero first byte.
    # Native unchecked skip deliberately checks bounds, not canonicality.
    for n in (3, 7, 16, 32):
        width = (n - 1).bit_length()
        for length in range(1 << width):
            prefix = f"{length:0{width}b}"
            values = (
                [b""]
                if length == 0
                else [bytes([first]) + b"\xff" * (length - 1) for first in (0, 1, 128, 255)]
            )
            for data in values:
                first = data[0] if data else 0
                bits = prefix + "".join(f"{byte:08b}" for byte in data)
                add(
                    f"n{n}-len{length}-first{first}",
                    "read",
                    n,
                    bits,
                    length < n and (length == 0 or first != 0),
                    int(length < n),
                    int.from_bytes(data, "big"),
                )
                if first == 255:
                    add(f"n{n}-len{length}-truncated", "read", n, bits[:-1], False, 0)
            if length == 1:
                add(f"n{n}-len1-zero", "read", n, prefix + "0" * 8, False, 1)
        for count in range(width):
            add(f"n{n}-header{count}", "read", n, "0" * count, False, 0)
        maximum = (1 << (8 * (n - 1))) - 1
        for ordinal, value in enumerate((0, -1, 1, 255, 256, maximum, maximum + 1)):
            add(f"n{n}-write{ordinal}", "write", n, str(value), 0 <= value <= maximum, value=value)
    assert len(result) == len({row["name"] for row in result}) == 330
    return result


def expected_output():
    return "".join("\t".join(row["expected"]) + "\n" for row in cases()).encode()


def compare_outputs(native, rust):
    assert len(native) <= MAX_OUTPUT and len(rust) <= MAX_OUTPUT, "codec output byte limit"
    expected = expected_output()
    assert native == expected, "native codec disagrees with authored rules/roots"
    assert rust == native, "native/Rust unsigned codec mismatch"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    data = "".join(
        "\t".join([row["name"], row["op"], str(row["n"]), row["data"]]) + "\n" for row in cases()
    ).encode()
    inputs = output / "inputs.tsv"
    inputs.write_bytes(data)
    native, _ = execute([str(args.native.resolve()), str(inputs)], output, "native")
    rust, _ = execute([str(args.rust.resolve()), str(inputs)], output, "rust")
    compare_outputs(native, rust)
    (output / "result.json").write_text(
        json.dumps(
            dict(
                cases=330,
                passed=True,
                harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                source=subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
                ).strip(),
                source_diff_sha256=hashlib.sha256(
                    subprocess.check_output(
                        ["git", "diff", "HEAD"],
                        cwd=ROOT,
                    )
                ).hexdigest(),
                inputs_sha256=hashlib.sha256(data).hexdigest(),
                native_binary_sha256=binary_hash(args.native),
                rust_binary_sha256=binary_hash(args.rust),
                native_sha256=hashlib.sha256(native).hexdigest(),
                rust_sha256=hashlib.sha256(rust).hexdigest(),
            ),
            indent=2,
        )
        + "\n"
    )
    print(
        "PASS: 330 authored unsigned-integer codec rows; exact native/Rust results and canonical roots"
    )


if __name__ == "__main__":
    main()
