"""Time full native transaction replay, verifying every sample against a parity receipt.

This measures the emulator C API, including BOC decoding and result serialization.
It excludes Python receipt decoding, setup and warmup. Repeated public fixtures are
warm-cache measurements, not worst-case hardware pricing or network admission proof.
"""

import argparse
import ctypes
import hashlib
import json
import os
import platform
import statistics
import subprocess
import time
from pathlib import Path

from fee_tx_parity import Cell, credit, from_boc, native, transcript


def fingerprint(path):
    path = Path(path).resolve()
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": str(path), "sha256": digest.hexdigest(), "bytes": path.stat().st_size}


def check_receipt(name, result, expected):
    if result["success"]:
        result["details"] = native.transaction_details(from_boc(result["transaction"]))
    actual = transcript(name, result)
    if actual != expected:
        raise ValueError(f"replay differs: {actual!r} != {expected!r}")


def run(fixtures, output, iterations, warmup):
    if not 1 <= iterations <= 10000 or not 1 <= warmup <= 100:
        raise ValueError("iterations must be 1..10000 and warmup 1..100")
    # Never overwrite prior evidence, including after a failed invocation.
    output.mkdir(parents=True, exist_ok=False)
    paths = [fixtures / name for name in ("config.boc", "scenarios.tsv", "native.tsv")]
    configuration = from_boc(paths[0].read_bytes()).refs[0]
    rows = [line.split("\t") for line in paths[1].read_text().splitlines()]
    expected = paths[2].read_text().splitlines()
    if not rows or len(rows) != len(expected) or len({r[0] for r in rows}) != len(rows):
        raise ValueError("empty, duplicate or incomplete fixture set")
    emulator = native.Emulator(vm_log_verbosity=0)
    results = []
    try:
        lib = emulator.lib
        lib.transaction_emulator_set_config.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lib.transaction_emulator_set_config.restype = ctypes.c_bool
        for setter in (
            "transaction_emulator_set_unixtime",
            "transaction_emulator_set_lt",
            "transaction_emulator_set_ignore_chksig",
        ):
            getattr(lib, setter).restype = ctypes.c_bool
        if not lib.transaction_emulator_set_config(emulator.ptr, configuration.b64()):
            raise ValueError("configuration rejected")
        if not lib.transaction_emulator_set_ignore_chksig(emulator.ptr, False):
            raise ValueError("cannot enable signature verification")
        for row, receipt in zip(rows, expected, strict=True):
            if len(row) != 6 or row[5] != "-":
                raise ValueError("unsupported scenario shape or libraries")
            name, now, lt, account_hex, message_hex, _ = row
            account = from_boc(bytes.fromhex(account_hex))
            shard = Cell().uint(0, 256).uint(0, 64).ref(account).b64()
            message = from_boc(bytes.fromhex(message_hex)).b64()
            samples = []
            for sample in range(warmup + iterations):
                if not lib.transaction_emulator_set_unixtime(emulator.ptr, int(now)):
                    raise ValueError("time rejected")
                if not lib.transaction_emulator_set_lt(emulator.ptr, int(lt)):
                    raise ValueError("logical time rejected")
                start = time.perf_counter_ns()
                ptr = lib.transaction_emulator_emulate_transaction(emulator.ptr, shard, message)
                elapsed = time.perf_counter_ns() - start
                if not ptr:
                    raise ValueError("emulator returned no result")
                try:
                    result = json.loads(ctypes.string_at(ptr))
                finally:
                    lib.string_destroy(ptr)
                check_receipt(name, result, receipt)
                if sample >= warmup:
                    samples.append(elapsed)
            results.append(
                {
                    "name": name,
                    "samples_ns": samples,
                    "min_ns": min(samples),
                    "median_ns": statistics.median(samples),
                    "max_ns": max(samples),
                    "expected_receipt": receipt,
                }
            )
    finally:
        emulator.close()
    report = {
        "scope": "Full native C API; warm-cache public fixtures; not worst-case or release clearance",
        "gas_credit": credit(configuration),
        "iterations": iterations,
        "warmup": warmup,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "head": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=native.ROOT, text=True
        ).strip(),
        "inputs": [fingerprint(path) for path in paths],
        "emulator": fingerprint(os.environ["EMULATOR_PATH"]),
        "runner": fingerprint(__file__),
        "results": results,
    }
    (output / "measurements.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "transactions": len(results),
                "verified_samples": len(results) * (iterations + warmup),
                "gas_credit": report["gas_credit"],
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=5)
    args = parser.parse_args()
    run(args.fixtures.resolve(), args.output.resolve(), args.iterations, args.warmup)
