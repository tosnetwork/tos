"""Probe every successful recorded fee external at its exact admission boundary in both VMs."""

import argparse
import ctypes
import json
import subprocess
from pathlib import Path

from benchmark_transactions import check_receipt, fingerprint
from cells import make_dict
from fee_tx_parity import Cell, credit, from_boc, native, read_dict, transcript


def configuration(root, amount):
    assert 0 <= amount <= 20000
    entries = read_dict(root.refs[0], 32)
    prices = entries[21].refs[0]
    prefix = 136 if int(prices.bits[:8], 2) == 0xD1 else 0
    assert int(prices.bits[prefix : prefix + 8], 2) == 0xDE
    offset = prefix + 8 + 64 * 3
    entries[21] = Cell().ref(
        Cell(
            bits=prices.bits[:offset] + format(amount, "064b") + prices.bits[offset + 64 :],
            refs=prices.refs,
        )
    )
    changed = Cell(bits=root.bits, refs=[make_dict(entries, 32)])
    assert credit(changed.refs[0]) == amount
    return changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    root = from_boc((args.fixtures / "config.boc").read_bytes())
    assert credit(root.refs[0]) == 20000
    rows = (args.fixtures / "scenarios.tsv").read_text().splitlines()
    receipts = (args.fixtures / "native.tsv").read_text().splitlines()
    assert len(rows) == len(receipts) and rows
    results = []
    emulator = native.Emulator(17, vm_log_verbosity=0)
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
                    assert result["vm_exit_code"] == -14 or (
                        amount == 0 and result["vm_exit_code"] == 0
                    ), (name, amount, result)
                probes.append({"credit": amount, "accepted": result["success"]})
                return cfg, result

            assert probe(20000)[1]["success"]
            assert not probe(0)[1]["success"]
            low, high = 0, 20000
            while low + 1 < high:
                mid = (low + high) // 2
                if probe(mid)[1]["success"]:
                    high = mid
                else:
                    low = mid
            for amount in (high - 1, high):
                cfg, result = probe(amount)
                assert result["success"] == (amount == high)
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
                        "17",
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
                }
            )
    finally:
        emulator.close()
    assert len(results) >= 6, "missing funded recovery fee cases"
    report = {
        "scope": "Exact recorded successful fee externals; not a worst-case envelope bound or production activation",
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
