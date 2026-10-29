"""Runtime external credit is independent of the produced transaction's wire width."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "test/auth-extensions"), str(ROOT / "test/rel02")]
import native  # noqa: E402
from cells import Cell, from_boc, make_dict, read_dict  # noqa: E402
from run_rust import binary_hash, execute  # noqa: E402

ADDRESS = (0, 0x6767)


def configuration(credit, contract, usage=None):
    entries = read_dict(native.config(16), 32)
    gas = entries[21].refs[0].slice()
    updated = Cell()
    tag = gas.uint(8)
    if tag == 0xD1:
        updated.uint(tag, 8).uint(gas.uint(128), 128)
        tag = gas.uint(8)
    assert tag == 0xDE
    price = gas.uint(64)
    gas.uint(64)
    special = gas.uint(64)
    gas.uint(64)
    updated.uint(tag, 8).uint(price, 64).uint(1 << 34, 64).uint(special, 64).uint(credit, 64)
    updated.uint(gas.uint(3 * 64), 3 * 64)
    assert not gas.bits and not gas.refs
    entries[21] = Cell().ref(updated)
    if usage is not None:
        listing = make_dict(
            {int.from_bytes(contract.hash, "big"): Cell().uint(0xB0, 8).uint(usage, 64)}, 256
        )
        entries[45] = Cell().ref(Cell().uint(0xC0, 8).maybe(listing))
    return make_dict(entries, 32)


def cases():
    rows = []
    accept, no_accept = Cell().raw(bytes.fromhex("f800")), Cell()
    throws = Cell().raw(bytes.fromhex("f22a"))
    for credit in (65535, 65536, 1 << 32, (1 << 32) + 1):
        for usage in (None, 5000):
            for accepts, contract in ((False, no_accept), (True, accept)):
                expected = (
                    "accepted"
                    if accepts and credit == 65535
                    else "encode-rejected"
                    if accepts
                    else "unaccepted:0"
                )
                rows.append(
                    (f"credit-{credit}-{usage}-{accepts}", credit, contract, usage, expected)
                )
        rows.append((f"throw-{credit}", credit, throws, None, "unaccepted:42"))
        rows.append((f"skip-{credit}", credit, accept, (1 << 34) + 1, "unaccepted:0"))
    # Burn over 65536 gas, then throw. A wire-width clamp incorrectly cuts off
    # the larger credit before the authored exception can be reached.
    burn = Cell().raw(bytes.fromhex("95f807830fbce6f22a"))
    for credit, expected in ((65535, "unaccepted:-14"), (131072, "unaccepted:42")):
        rows.append((f"burn-{credit}", credit, burn, None, expected))
    return rows


def classify(result):
    if result["success"]:
        tx, shard = from_boc(result["transaction"]), from_boc(result["shard_account"])
        return dict(
            outcome="accepted",
            transaction=tx.hash.hex(),
            account=shard.refs[0].hash.hex(),
            shard_account=shard.hash.hex(),
        )
    assert "transaction" not in result and "shard_account" not in result
    if result.get("external_not_accepted"):
        return dict(outcome=f"unaccepted:{result['vm_exit_code']}")
    return dict(outcome="encode-rejected")


def worker(library, output):
    os.environ["EMULATOR_PATH"] = str(library)
    rows = []
    for name, credit, contract, usage, _ in cases():
        cfg = configuration(credit, contract, usage)
        shard = native.active_account(ADDRESS, contract, Cell(), 10**18)
        message = native.external(ADDRESS, Cell())
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
        rows.append(dict(name=name, inputs=inputs, **classify(result)))
    (output / "outcomes.json").write_text(json.dumps(rows, indent=2) + "\n")


def compare_reports(native_rows, rust_rows):
    expected = cases()
    assert len(native_rows) == len(expected), "credit case population"
    for row, case in zip(native_rows, expected, strict=True):
        assert row["name"] == case[0] and row["outcome"] == case[4], (case[0], row)
        fields = {"name", "inputs", "outcome"}
        if case[4] == "accepted":
            fields |= {"transaction", "account", "shard_account"}
        assert set(row) == fields and set(row["inputs"]) == {"config", "shard", "message"}
        hashes = [
            *row["inputs"].values(),
            *[row[k] for k in fields - {"name", "inputs", "outcome"}],
        ]
        assert all(isinstance(h, str) and re.fullmatch("[0-9a-f]{64}", h) for h in hashes)
    assert native_rows == rust_rows, (
        "native/Rust runtime-credit outcomes, original inputs or accepted roots differ"
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
        report = directory / "outcomes.json"
        assert report.stat().st_size <= 1024 * 1024, "credit report exceeds byte limit"
        reports.append(json.loads(report.read_text()))
    expected = cases()
    compare_reports(*reports)
    for case in expected:
        if case[4] == "encode-rejected":
            result = json.loads((output / "native" / f"{case[0]}.json").read_text())
            assert "cannot serialize new transaction" in result["error"], result
    (output / "result.json").write_text(
        json.dumps(
            dict(
                cases=len(expected),
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
                native_output_sha256=hashlib.sha256(
                    (output / "native/outcomes.json").read_bytes()
                ).hexdigest(),
                rust_output_sha256=hashlib.sha256(
                    (output / "rust/outcomes.json").read_bytes()
                ).hexdigest(),
            ),
            indent=2,
        )
        + "\n"
    )
    print(
        f"PASS: {len(expected)} runtime-credit cases and accepted transaction/account/shard roots"
    )


if __name__ == "__main__":
    main()
