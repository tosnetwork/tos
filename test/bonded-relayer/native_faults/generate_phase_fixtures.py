#!/usr/bin/env python3
"""Generate bounded synthetic C++-executor phase fixtures at global version16/id3."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "test/bonded-relayer/fixtures/native-refusal/phases.fc"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    for key in ("FUNC_PATH", "FIFT_PATH", "EMULATOR_PATH"):
        if not os.environ.get(key):
            parser.error(key + " is required; no green skips")
    args.out.mkdir(mode=0o700, exist_ok=False)
    sys.path.insert(0, str(ROOT / "test/pq-contracts"))
    import pqtest
    from native import Emulator, account_data, active_account, config, internal

    configuration = pqtest.read_dict(config(global_version=16), 32)
    configuration[19] = pqtest.Cell().ref(pqtest.Cell().sint(3, 32))
    configuration = pqtest.make_dict(configuration, 32)
    cases = []
    with tempfile.TemporaryDirectory(prefix="br1-phase-compile-") as directory:
        code = pqtest.compile_source(SOURCE, Path(directory) / "code.boc")
        for name, mode, count, expected in [
            ("gas-positive", 0, 5, 5),
            ("gas-exhausted", 0, 1000000000, 0),
            ("action-positive", 1, 1, 7),
            ("action-no-funds", 1, 1000000000000000000, 0),
        ]:
            initial = pqtest.Cell().uint(0, 32)
            account = active_account((0, 200), code, initial, balance=1000000000)
            emulator = Emulator.from_config(configuration)
            try:
                result = emulator.send(
                    account,
                    internal(
                        (0, 201),
                        (0, 200),
                        pqtest.Cell().uint(mode, 32).uint(count, 64),
                        value=100000000,
                    ),
                )
            finally:
                emulator.close()
            if not result["success"]:
                raise RuntimeError("native executor did not produce a transaction")
            details = result["details"]
            data, _ = account_data(pqtest.from_boc(result["shard_account"]))
            if data.slice().uint(32) != expected:
                raise RuntimeError("native data commit/rollback control failed: " + name)
            if name == "gas-exhausted":
                if details["exit"] != -14 or details["compute_success"] or not details["aborted"]:
                    raise RuntimeError("not the intended out-of-gas failure")
            elif name == "action-no-funds":
                if (
                    details["exit"] != 0
                    or not details["compute_success"]
                    or not details["aborted"]
                    or details["action"]["success"]
                    or details["action"]["code"] != 37
                ):
                    raise RuntimeError("not the intended action-phase insufficient-funds failure")
            elif details["exit"] != 0 or details["aborted"] or not details["action"]["success"]:
                raise RuntimeError("positive control never executed")
            raw = base64.b64decode(result["transaction"], validate=True)
            if len(raw) > 4096:
                raise RuntimeError("bounded synthetic fixture size")
            file = args.out / (name + ".boc")
            file.write_bytes(raw)
            cases.append(
                {
                    "name": name,
                    "mode": mode,
                    "count": count,
                    "data_after": expected,
                    "transaction_bytes": len(raw),
                    "sha256": digest(file),
                    "details": details,
                }
            )
    manifest = {
        "schema": "tos.br1.synthetic-native-phase-fixtures.v1",
        "synthetic_not_network": True,
        "global_version": 16,
        "global_id": 3,
        "source_sha256": digest(SOURCE),
        "config_sha256": hashlib.sha256(base64.b64decode(configuration.b64())).hexdigest(),
        "emulator_sha256": digest(Path(os.environ["EMULATOR_PATH"])),
        "cases": cases,
        "public_retention": "Normal Git history; no scheduled expiry. No keys, tokens or live payloads.",
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("NATIVE_PHASE_FIXTURES_PASS", len(cases), "real compute/action controls")


if __name__ == "__main__":
    main()
