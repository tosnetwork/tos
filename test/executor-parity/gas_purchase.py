"""Authored gas-purchase arithmetic, checked against independent native/Rust adapters."""

import argparse
import hashlib
import itertools
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/rel02"))
from run_rust import binary_hash, execute  # noqa: E402

MASK = (1 << 64) - 1
MIN = -(1 << 63)
MAX = (1 << 63) - 1
MAX_OUTPUT = 1024 * 1024


def signed(value):
    value &= MASK
    return value if value <= MAX else value - (1 << 64)


def expected(price, limit, flat, fee, value):
    # RefInt256 scalar overloads and make_bigint take signed 64-bit arguments;
    # make_refint's unsigned constructor in the other branch retains all bits.
    threshold = fee
    if limit > flat:
        product = price * signed(limit - flat)
        threshold = signed(fee) - (-product // 65536)
    if value >= threshold:
        return threshold, limit
    if value < signed(fee):
        return threshold, 0
    numerator = (value + signed(-signed(fee))) * 65536
    quotient = numerator // price if price else None
    native_long = quotient if quotient is not None and MIN <= quotient <= MAX else MIN
    return threshold, (native_long + flat) & MASK


def cases():
    rows = []
    for price, limit, flat, fee in itertools.product(
        [0, 1, 65535, 65536, 65537, 1 << 63, MASK],
        [0, 100, 1000000, 1 << 50, MAX, 1 << 63, MASK],
        [0, 100, 1 << 63, MASK],
        [0, 100, 1 << 63, MASK],
    ):
        threshold = expected(price, limit, flat, fee, 0)[0]
        values = sorted(
            {0, 99, 100, 1 << 49, MAX, 1 << 63, MASK, *[max(0, threshold + k) for k in (-1, 0, 1)]}
        )
        for value in values:
            name = f"purchase-{len(rows)}"
            args = price, limit, flat, fee, value
            rows.append((name, args, expected(*args)))
    return rows


def expected_output():
    return "".join(
        f"{name}\t{threshold}\t{gas}\n" for name, _, (threshold, gas) in cases()
    ).encode()


def compare_outputs(native, rust):
    assert len(native) <= MAX_OUTPUT and len(rust) <= MAX_OUTPUT, "gas purchase output byte limit"
    assert native == expected_output(), "native gas purchase differs from authored scalar rules"
    assert rust == native, "native/Rust gas threshold or purchased gas differs"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    directory = args.output.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "result.json").unlink(missing_ok=True)
    rows = cases()
    data = "".join("\t".join([name, *map(str, values)]) + "\n" for name, values, _ in rows).encode()
    inputs = directory / "inputs.tsv"
    inputs.write_bytes(data)
    for label, executable in (("native", args.native), ("rust", args.rust)):
        execute([str(executable.resolve()), str(inputs)], directory, label)
    native = (directory / "native.stdout").read_bytes()
    rust = (directory / "rust.stdout").read_bytes()
    compare_outputs(native, rust)
    result = dict(
        cases=len(rows),
        passed=True,
        source=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        source_diff_sha256=hashlib.sha256(
            subprocess.check_output(["git", "diff", "HEAD"], cwd=ROOT)
        ).hexdigest(),
        harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        inputs_sha256=hashlib.sha256(data).hexdigest(),
        native_binary_sha256=binary_hash(args.native),
        rust_binary_sha256=binary_hash(args.rust),
        native_sha256=hashlib.sha256(native).hexdigest(),
        rust_sha256=hashlib.sha256(rust).hexdigest(),
    )
    (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"PASS: {len(rows)} authored native/Rust gas-purchase thresholds and budgets")


if __name__ == "__main__":
    main()
