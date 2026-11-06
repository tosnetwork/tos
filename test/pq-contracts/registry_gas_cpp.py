#!/usr/bin/env python3
"""Run the registry-shaped ML-DSA-44 probe cases exported by the Rust sandbox test
(tosctl/src/node-control/contracts/tests/pq_registry_gas_sandbox.rs, PQ_REGISTRY_GAS_OUT)
on the real C++ transaction emulator, at global version 16 with the genesis
ConfigParam 43, and print the compute gas next to the Rust VM's.

Usage: registry_gas_cpp.py --build <tos build dir> --cases <cases.json>
"""

import argparse
import base64
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", required=True)
    parser.add_argument("--cases", required=True)
    parser.add_argument("--out")
    args = parser.parse_args()
    build = Path(args.build).resolve()
    os.environ["EMULATOR_PATH"] = str(build / "emulator/libemulator.so")
    os.environ["FUNC_PATH"] = str(build / "crypto/func")
    os.environ["FIFT_PATH"] = str(build / "crypto/fift")
    import native
    from cells import from_boc

    limits, fields = native.genesis_size_limits()
    print(
        "genesis ConfigParam 43: max_msg_cells={} max_msg_bits={} max_ext_msg_size={}".format(
            fields["max_msg_cells"], fields["max_msg_bits"], fields["max_ext_msg_size"]
        )
    )
    emulator = native.Emulator(global_version=16, limits=limits)
    rows = []
    for case in json.loads(Path(args.cases).read_text()):
        code = from_boc(base64.b64decode(case["code_boc"]))
        data = from_boc(base64.b64decode(case["data_boc"]))
        body = from_boc(base64.b64decode(case["body_boc"]))
        workchain, account = case["address"].split(":")
        address = (int(workchain), int(account, 16))
        shard = native.active_account(address, code, data)
        message = native.internal((0, 0x77 * 1), address, body, value=10 * 10**9)
        result = emulator.send(shard, message)
        details = result.get("details") or {}
        row = {
            "controllers": case["controllers"],
            "hash_keys": case.get("hash_keys", case.get("path")),
            "rust_gas": case["gas_used"],
            "cpp_success": result["success"],
            "cpp_gas": details.get("gas"),
            "cpp_gas_limit": details.get("gas_limit"),
            "cpp_exit": details.get("exit"),
            "body_cells": case.get("body_cells", case.get("external_bytes")),
            "error": result.get("error"),
        }
        rows.append(row)
        print(
            "controllers={controllers:>2} hash_keys={hash_keys!s:<5} rust_gas={rust_gas:>8} "
            "cpp_gas={cpp_gas!s:>8} cpp_exit={cpp_exit!s} cpp_limit={cpp_gas_limit!s} "
            "body_cells={body_cells} error={error}".format(**row)
        )
    emulator.close()
    if args.out:
        Path(args.out).write_text(json.dumps(rows, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
