"""Execute PQ probes in real transactions with an unchanged generated config BOC.

This verifies configuration plumbing and opcode availability, not wallet release
acceptance or worst-case external-message admission. No signature is generated.
"""

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
from fee_tx_parity import transcript


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--driver", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    raw = args.config.read_bytes()
    root = from_boc(raw)
    assert len(root.bits) == 256 and len(root.refs) == 1, "ConfigParams required"
    entries = read_dict(root.refs[0], 32)
    version = entries[8].refs[0].slice()
    assert version.uint(8) == 0xC4 and version.uint(32) == 18
    policy = entries[48].refs[0].slice()
    assert policy.uint(8) == 0xA1
    namespace = policy.uint(256)
    assert namespace == int("42" * 32, 16), "unexpected generated AUTH namespace"
    code = native.compile_contract(
        str(Path(__file__).with_name("release-config-probe.fc")), out / "probe.boc"
    )
    inputs = [
        line.split("\t")
        for line in (ROOT / "test/rescue-fee-gate/suite-scenarios.tsv").read_text().splitlines()
    ]
    fixtures = {row[0]: row for row in inputs}
    names = [f"s{suite}-{kind}" for suite in range(1, 4) for kind in ("valid", "bitflip")]
    names += ["s4-h20w4-valid", "s4-h20w4-bitflip"]
    cases = [(name, fixtures[name], False) for name in names]
    cases += [("dedicated-" + name, fixtures[name], True) for name in ("s2-valid", "s2-bitflip")]
    scenarios, receipts, results = [], [], []
    now = 1_789_437_600  # One hour after the canonical candidate genesis.
    # The actual-config path must never ask for a synthesized fallback config.
    with patch.object(
        native, "config", side_effect=AssertionError("synthesized configuration forbidden")
    ):
        emulator = native.Emulator.from_config(root.refs[0], vm_log_verbosity=0)
    emulator.lib.transaction_emulator_set_unixtime(emulator.ptr, now)
    try:
        for index, (name, fixture, dedicated) in enumerate(cases):
            suite = 255 if dedicated else int(fixture[4].split(":")[1])
            data = Cell().uint(suite, 8)
            for operand in fixture[5:9]:
                data.ref(from_boc(bytes.fromhex(operand)))
            address = (0, 1000 + index)
            with patch.object(native, "NOW", now):
                shard = native.active_account(address, code, data, 100_000_000_000)
                message = native.internal((0, 999), address, Cell(), value=10_000_000_000)
            result = emulator.send(shard, message)
            assert result["success"], (name, result)
            details = result["details"]
            expected = (
                6 if dedicated else 5 if suite == 2 else 901 if name.endswith("bitflip") else 0
            )
            assert details["exit"] == expected, (name, expected, details)
            state, _ = native.account_data(from_boc(result["shard_account"]))
            if expected == 0:
                assert state.hash == Cell().uint(1, 1).hash
                assert details["compute_success"] and not details["aborted"]
                assert details["action"] == {"success": True, "code": 0}
            else:
                assert state.hash == data.hash, (name, "rejected probe changed state")
                assert not details["compute_success"] and details["aborted"]
            assert not native.outgoing(from_boc(result["transaction"]))
            scenarios.append(
                "\t".join(
                    [
                        name,
                        str(now),
                        str(emulator.lt),
                        shard.refs[0].boc().hex(),
                        message.boc().hex(),
                        "-",
                    ]
                )
            )
            receipts.append(transcript(name, result))
            results.append(
                dict(
                    name=name, exit=details["exit"], gas=details["gas"], state_changed=expected == 0
                )
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
    assert rust.returncode == 0, rust.stderr[-2000:]
    assert rust.stdout.splitlines() == receipts, "whole-transaction cross-VM divergence"
    assert args.config.read_bytes() == raw
    report = dict(
        passed=True,
        config_sha256=hashlib.sha256(raw).hexdigest(),
        config_root=root.refs[0].hash.hex(),
        version=18,
        namespace=f"{namespace:064x}",
        rust_command=command,
        cases=results,
        scope="Generated config unchanged; whole transactions for PQ availability and rejected-state preservation; not full wallet or external admission acceptance",
    )
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
