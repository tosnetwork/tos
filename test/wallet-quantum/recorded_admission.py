"""Probe recorded fee externals at G-1/G and historical credit in both VMs.

The unchanged input configuration establishes the baseline. Credit-only variants
measure acceptance boundaries; they are not replacement release configurations.
"""

import argparse
import ctypes
import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from benchmark_transactions import check_receipt, fingerprint
from cells import make_dict
from fee_tx_parity import Cell, from_boc, native, read_dict, transcript

HISTORICAL_CREDIT = 10000


def config_profile(root):
    assert len(root.bits) == 256 and len(root.refs) == 1, "ConfigParams required"
    entries = read_dict(root.refs[0], 32)
    version = entries[8].refs[0].slice()
    assert version.uint(8) == 0xC4, "invalid ConfigParam 8"
    global_version = version.uint(32)
    version.uint(64)
    assert not version.bits and not version.refs, "trailing ConfigParam 8 fields"
    return {
        "global_version": global_version,
        "basechain_credit": gas_credit(entries[21].refs[0])[0],
        "masterchain_credit": gas_credit(entries[20].refs[0])[0],
    }


def gas_credit(prices):
    """Read the credit and its bit offset from a canonical dd/de gas-price cell."""
    cursor = prices.slice()
    tag = cursor.uint(8)
    prefix = 0
    if tag == 0xD1:
        cursor.uint(128)
        prefix = 136
        tag = cursor.uint(8)
    assert tag in (0xDD, 0xDE), "invalid gas-price constructor"
    fields_before_credit = 3 if tag == 0xDE else 2
    cursor.uint(fields_before_credit * 64)
    amount = cursor.uint(64)
    cursor.uint(3 * 64)
    assert not cursor.bits and not cursor.refs, "trailing gas-price fields"
    return amount, prefix + 8 + fields_before_credit * 64


def configuration(root, amount):
    entries = read_dict(root.refs[0], 32)
    prices = entries[21].refs[0]
    original_credit, offset = gas_credit(prices)
    assert 0 <= amount <= original_credit, "probe cannot increase configured credit"
    if amount == original_credit:
        return root
    entries[21] = Cell().ref(
        Cell(
            bits=prices.bits[:offset] + format(amount, "064b") + prices.bits[offset + 64 :],
            refs=prices.refs,
        )
    )
    changed = Cell(bits=root.bits, refs=[make_dict(entries, 32)])
    changed_entries = read_dict(changed.refs[0], 32)
    assert gas_credit(changed_entries[21].refs[0])[0] == amount
    assert {k: v.hash for k, v in entries.items() if k != 21} == {
        k: v.hash for k, v in changed_entries.items() if k != 21
    }, "admission probe changed unrelated configuration"
    return changed


def require_release_config(raw, release_raw, profile):
    assert raw == release_raw, "recorded configuration differs from frozen release input"
    assert profile == {
        "global_version": 18,
        "basechain_credit": 20000,
        "masterchain_credit": 10000,
    }, "unexpected release admission profile"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--release-config",
        type=Path,
        help="Require the exact frozen version-18 candidate ConfigParams BOC",
    )
    parser.add_argument("--minimum-fee-cases", type=int, default=6)
    args = parser.parse_args()
    assert args.minimum_fee_cases > 0
    args.output.mkdir(parents=True, exist_ok=False)
    raw_config = (args.fixtures / "config.boc").read_bytes()
    root = from_boc(raw_config)
    profile = config_profile(root)
    release_credit = profile["basechain_credit"]
    assert release_credit >= HISTORICAL_CREDIT
    if args.release_config:
        require_release_config(raw_config, args.release_config.read_bytes(), profile)
    rows = (args.fixtures / "scenarios.tsv").read_text().splitlines()
    receipts = (args.fixtures / "native.tsv").read_text().splitlines()
    assert len(rows) == len(receipts) and rows
    results = []
    # A synthesized configuration must never supply missing release fields.
    with patch.object(
        native, "config", side_effect=AssertionError("synthesized configuration forbidden")
    ):
        emulator = native.Emulator.from_config(root.refs[0], vm_log_verbosity=0)
    lib = emulator.lib
    lib.transaction_emulator_set_config.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.transaction_emulator_set_config.restype = ctypes.c_bool
    try:
        for row, receipt in zip(rows, receipts, strict=True):
            name, now, lt, account_hex, message_hex, libraries = row.split("\t")
            assert libraries == "-" and receipt.split("\t")[0] == name
            message = from_boc(bytes.fromhex(message_hex))
            if message.bits[:2] != "10" or receipt.split("\t")[1] != "0":
                continue
            fields = receipt.split("\t")
            assert fields[6] == "true" and fields[8:] == ["false", "true"], (
                "fee action did not succeed"
            )
            assert int(message.refs[0].refs[0].bits[:32], 2) == 0x46454534, (
                "unexpected external profile"
            )
            account = from_boc(bytes.fromhex(account_hex))
            shard = Cell().uint(0, 320).ref(account)
            probes = []

            def probe(amount):
                cfg = configuration(root, amount)
                assert lib.transaction_emulator_set_config(emulator.ptr, cfg.refs[0].b64())
                assert lib.transaction_emulator_set_unixtime(emulator.ptr, int(now))
                emulator.lt = int(lt) - 1_000_000  # send advances to the recorded transaction LT
                result = emulator.send(shard, message)
                if result["success"]:
                    check_receipt(name, result, receipt)
                else:
                    assert result.get("external_not_accepted") is True, (
                        name,
                        amount,
                        "probe failed outside external admission",
                    )
                    assert result["vm_exit_code"] == -14 or (
                        amount == 0 and result["vm_exit_code"] == 0
                    ), (name, amount, result)
                    assert "transaction" not in result and "shard_account" not in result, (
                        name,
                        amount,
                        "rejected admission returned committed state",
                    )
                probes.append({"credit": amount, "accepted": result["success"]})
                return cfg, result

            assert probe(release_credit)[1]["success"]
            assert not probe(0)[1]["success"]
            low, high = 0, release_credit
            while low + 1 < high:
                mid = (low + high) // 2
                if probe(mid)[1]["success"]:
                    high = mid
                else:
                    low = mid
            historical = None
            for amount in dict.fromkeys((high - 1, high, HISTORICAL_CREDIT)):
                cfg, result = probe(amount)
                assert result["success"] == (amount >= high)
                if amount == HISTORICAL_CREDIT:
                    historical = {
                        "credit": amount,
                        "accepted": result["success"],
                        "no_transaction_or_state_update": not result["success"],
                        "exit": result.get("vm_exit_code"),
                    }
                directory = args.output / f"{name}-{amount}"
                directory.mkdir()
                (directory / "config.boc").write_bytes(cfg.boc())
                selected = [row] + [other for other in rows if other.split("\t")[0] != name][:3]
                (directory / "scenarios.tsv").write_text("\n".join(selected) + "\n")
                expected_rows = [transcript(name, result)]
                for other in selected[1:]:
                    other_name, other_now, other_lt, other_account, other_message, _ = other.split(
                        "\t"
                    )
                    assert lib.transaction_emulator_set_unixtime(emulator.ptr, int(other_now))
                    emulator.lt = int(other_lt) - 1_000_000
                    observed = emulator.send(
                        Cell().uint(0, 320).ref(from_boc(bytes.fromhex(other_account))),
                        from_boc(bytes.fromhex(other_message)),
                    )
                    expected_rows.append(transcript(other_name, observed))
                expected = "\n".join(expected_rows)
                rust = subprocess.run(
                    [
                        str(args.driver.resolve()),
                        str(directory / "config.boc"),
                        str(directory / "scenarios.tsv"),
                        str(profile["global_version"]),
                        "--details",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                (directory / "rust.log").write_text(rust.stderr)
                (directory / "rust.tsv").write_text(rust.stdout)
                (directory / "native.tsv").write_text(expected + "\n")
                assert rust.returncode == 0 and rust.stdout.strip() == expected, (
                    name,
                    amount,
                    rust.stdout,
                )
            results.append(
                {
                    "name": name,
                    "minimum_credit": high,
                    "probes": probes,
                    "both_vm_boundary_match": True,
                    "historical_credit": historical,
                }
            )
    finally:
        emulator.close()
    assert len(results) >= args.minimum_fee_cases, "missing funded recovery fee cases"
    assert (args.fixtures / "config.boc").read_bytes() == raw_config
    if args.release_config:
        require_release_config(raw_config, args.release_config.read_bytes(), profile)
        assert max(r["minimum_credit"] for r in results) <= 18000, (
            "selected complete fee path exceeds release admission margin"
        )
    report = {
        "scope": "Exact recorded successful fee externals, G-1/G and historical 10000 credit; not a worst-case envelope bound or production activation",
        "configuration": profile,
        "frozen_release_config": args.release_config is not None,
        "transactions": results,
        "maximum_observed_minimum": max(r["minimum_credit"] for r in results),
        "inputs": [
            fingerprint(args.fixtures / n) for n in ("config.boc", "scenarios.tsv", "native.tsv")
        ],
        "rust_driver": fingerprint(args.driver),
    }
    (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "fee_transactions": len(results),
                "maximum_observed_minimum": report["maximum_observed_minimum"],
            }
        )
    )


if __name__ == "__main__":
    main()
