"""Measure ordinary account execution after ACCEPT on generated configuration."""

# ruff: noqa: E402
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "test/auth-extensions"), str(ROOT / "test/wallet-v5r2")]
import native
from cells import Cell, from_boc, read_dict
from fee_tx_parity import credit, transcript


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--driver", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--delete-accept", action="store_true")
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    raw = args.config.read_bytes()
    config = from_boc(raw).refs[0]
    assert credit(config) == 20000
    version = read_dict(config, 32)[8].refs[0].slice()
    assert version.uint(8) == 0xC4 and version.uint(32) == 18
    source = Path(__file__).with_name("post-accept-probe.fc")
    if args.delete_accept:
        original = source.read_text()
        assert original.count("accept_message();") == 1
        source = out / "without-accept.fc"
        source.write_text(original.replace("accept_message();", ""))
    code = native.compile_contract(str(source), out / "probe.boc")
    now = 1_789_437_600
    data = Cell().uint(0, 32)
    with patch.object(native, "NOW", now):
        initial = native.active_account((0, 7000), code, data, 10**15)
    emulator = native.Emulator.from_config(config, vm_log_verbosity=0)
    emulator.lib.transaction_emulator_set_unixtime(emulator.ptr, now)
    scenarios, receipts, measurements = [], [], []
    try:
        for name, accepted, count in [
            ("unaccepted-small", 0, 1),
            ("unaccepted-large", 0, 5000),
            ("accepted-small", 1, 1),
            ("accepted-large", 1, 5000),
            ("accepted-exhaustion", 1, 0x7FFFFFFF),
        ]:
            message = native.external((0, 7000), Cell().uint(accepted, 1).uint(count, 32))
            result = emulator.send(initial, message)
            scenarios.append(
                "\t".join(
                    [
                        name,
                        str(now),
                        str(emulator.lt),
                        initial.refs[0].boc().hex(),
                        message.boc().hex(),
                        "-",
                    ]
                )
            )
            receipts.append(transcript(name, result))
            if not accepted:
                assert not result["success"]
                assert result["vm_exit_code"] == (0 if count == 1 else -14)
                measurements.append(
                    dict(name=name, transaction_accepted=False, exit=result["vm_exit_code"])
                )
                continue
            assert result["success"], (name, "expected acceptance", result)
            details = result["details"]
            state, _ = native.account_data(from_boc(result["shard_account"]))
            if count == 0x7FFFFFFF:
                assert details["exit"] == -14 and details["aborted"]
                assert state.hash == data.hash
                assert details["gas"] == 30000000
            else:
                assert details["exit"] == 0 and not details["aborted"]
                assert state.hash == Cell().uint(count, 32).hash
                if count == 5000:
                    assert details["gas"] > 20000
            measurements.append(
                dict(name=name, transaction_accepted=True, exit=details["exit"], gas=details["gas"])
            )
    finally:
        emulator.close()
    (out / "config.boc").write_bytes(raw)
    (out / "scenarios.tsv").write_text("\n".join(scenarios) + "\n")
    (out / "native.tsv").write_text("\n".join(receipts) + "\n")
    command = [
        str(args.driver.resolve()),
        str(out / "config.boc"),
        str(out / "scenarios.tsv"),
        "18",
        "--details",
    ]
    rust = subprocess.run(command, capture_output=True, text=True)
    (out / "rust.tsv").write_text(rust.stdout)
    (out / "rust.log").write_text(rust.stderr)
    assert rust.returncode == 0 and rust.stdout.splitlines() == receipts, (
        "post-ACCEPT transaction divergence"
    )
    assert args.config.read_bytes() == raw
    report = dict(
        passed=True,
        config_sha256=hashlib.sha256(raw).hexdigest(),
        measurements=measurements,
        command=command,
        scope="Ordinary funded owner-controlled account; whole transactions, not actual node dispatch or CPU calibration",
    )
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
