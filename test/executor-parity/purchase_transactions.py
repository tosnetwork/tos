"""Actual transaction roots and serialization boundaries for gas-purchase rules."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import gas_purchase

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
import native  # noqa: E402
from cells import Cell, make_dict, read_dict  # noqa: E402
from gas_credit import classify  # noqa: E402
from run_rust import binary_hash, execute  # noqa: E402

ADDRESS = (0, 0x6868)
WIRE_MAX = (1 << 48) - 1


def cases():
    # name, price, limit, flat gas, flat fee, message value, account balance
    return [
        ("wire-max", 65536, 1 << 50, 0, 0, WIRE_MAX, 1 << 60),
        ("wire-over", 65536, 1 << 50, 0, 0, WIRE_MAX + 1, 1 << 60),
        ("wire-half-limit", 65536, 1 << 50, 0, 0, 1 << 49, 1 << 60),
        ("ceil-low-price", 1, 1000000, 0, 0, 15, 1 << 60),
        ("ceil-unit-over", 65537, 1000000, 0, 0, 1000015, 1 << 60),
        ("ceil-zero-value", 1, 100, 0, 0, 0, 1 << 60),
        ("ceil-one-value", 1, 100, 0, 0, 1, 1 << 60),
        ("flat-below", 65536, 1000000, 100, 100, 99, 1 << 60),
        ("flat-at", 65536, 1000000, 100, 100, 100, 1 << 60),
        ("negative-threshold-funded", 65536, 1000, 100, 1 << 63, 0, 1 << 100),
        ("signed-flat-funded", 65536, 1000, 100, (1 << 64) - 1, 898, 1 << 100),
    ]


def configuration(price, limit, flat, fee):
    entries = read_dict(native.config(16), 32)
    prices = entries[21].refs[0].slice()
    tag = prices.uint(8)
    if tag == 0xD1:
        prices.uint(128)
        tag = prices.uint(8)
    assert tag == 0xDE
    values = [prices.uint(64) for _ in range(7)]
    assert not prices.bits and not prices.refs
    values[:2] = [price, limit]
    updated = Cell().uint(0xD1, 8).uint(flat, 64).uint(fee, 64).uint(0xDE, 8)
    for value in values:
        updated.uint(value, 64)
    entries[21] = Cell().ref(updated)
    return make_dict(entries, 32)


def worker(library, output):
    os.environ["EMULATOR_PATH"] = str(library)
    rows = []
    for name, price, limit, flat, fee, value, balance in cases():
        cfg = configuration(price, limit, flat, fee)
        contract = Cell().raw(bytes.fromhex("f800"))
        shard = native.active_account(ADDRESS, contract, Cell(), balance)
        message = native.internal((0, 0x9999), ADDRESS, Cell(), value)
        inputs = {}
        for kind, cell in (("config", cfg), ("shard", shard), ("message", message)):
            (output / f"{name}.{kind}.boc").write_bytes(cell.boc())
            inputs[kind] = cell.hash.hex()
        emulator = native.Emulator.from_config(cfg, vm_log_verbosity=0)
        try:
            result = emulator.send(shard, message)
        finally:
            emulator.close()
        (output / f"{name}.json").write_text(json.dumps(result, indent=2) + "\n")
        row = dict(name=name, inputs=inputs, **classify(result))
        if result["success"]:
            row["compute"] = result["details"]
        rows.append(row)
    (output / "outcomes.json").write_text(json.dumps(rows, indent=2) + "\n")


def compare_reports(native_rows, rust_rows):
    assert len(native_rows) == len(cases()), "purchase transaction population"
    for row, case in zip(native_rows, cases(), strict=True):
        name, price, limit, flat, fee, value, balance = case
        assert row["name"] == name
        gas_max = gas_purchase.expected(price, limit, flat, fee, balance + value)[1]
        budget = min(gas_max, gas_purchase.expected(price, limit, flat, fee, value)[1])
        fields = {"name", "inputs", "outcome"}
        if budget <= WIRE_MAX:
            fields |= {"transaction", "account", "shard_account", "compute"}
        assert set(row) == fields and set(row["inputs"]) == {"config", "shard", "message"}
        hashes = [*row["inputs"].values()]
        if budget <= WIRE_MAX:
            hashes += [row[k] for k in ("transaction", "account", "shard_account")]
        assert all(isinstance(h, str) and re.fullmatch("[0-9a-f]{64}", h) for h in hashes)
        if budget > WIRE_MAX:
            assert row["outcome"] == "encode-rejected" and "compute" not in row, row
        else:
            assert row["outcome"] == "accepted", row
            compute = row["compute"]
            if budget == 0:
                assert compute == dict(exit=None, skipped=True, reason="100"), row
            else:
                assert (
                    compute["gas_limit"] == budget
                    and compute["exit"] == 0
                    and compute["compute_success"]
                    and not compute["aborted"]
                ), row
                assert compute["gas"] == 31 and compute["action"] == dict(success=True, code=0), row
    assert native_rows == rust_rows, (
        "native/Rust purchase transaction outcomes, original inputs or roots differ"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path)
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--worker", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if args.worker:
        worker(args.worker.resolve(), output)
        return
    assert args.native and args.rust
    (output / "result.json").unlink(missing_ok=True)
    reports = []
    for label, library in (("native", args.native), ("rust", args.rust)):
        directory = output / label
        directory.mkdir(exist_ok=True)
        execute(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--worker",
                str(library.resolve()),
                "--output",
                str(directory),
            ],
            output,
            label,
        )
        path = directory / "outcomes.json"
        assert path.stat().st_size <= 1024 * 1024, "transaction report byte limit"
        reports.append(json.loads(path.read_text()))
    compare_reports(*reports)
    for row in reports[0]:
        if row["outcome"] == "encode-rejected":
            result = json.loads((output / "native" / f"{row['name']}.json").read_text())
            assert "cannot serialize new transaction" in result["error"], result
    (output / "result.json").write_text(
        json.dumps(
            dict(
                cases=len(cases()),
                passed=True,
                source=subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
                ).strip(),
                source_diff_sha256=hashlib.sha256(
                    subprocess.check_output(["git", "diff", "HEAD"], cwd=ROOT)
                ).hexdigest(),
                harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                native_binary_sha256=binary_hash(args.native),
                rust_binary_sha256=binary_hash(args.rust),
            ),
            indent=2,
        )
        + "\n"
    )
    print(f"PASS: {len(cases())} purchase transaction outcomes, initial limits and complete roots")


if __name__ == "__main__":
    main()
