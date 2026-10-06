"""Replay actual fee delivery scenarios in Rust; diagnostic credit is not admission clearance."""

import argparse
import json
import runpy
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
sys.path.insert(0, str(ROOT / "test/wallet-v5r2"))
import native  # noqa: E402
from cells import Cell, from_boc, read_dict  # noqa: E402


def credit(configuration):
    prices = read_dict(configuration, 32)[21].refs[0].slice()
    tag = prices.uint(8)
    if tag == 0xD1:
        prices.uint(128)
        tag = prices.uint(8)
    assert tag == 0xDE
    prices.uint(64 * 3)
    return prices.uint(64)


def transcript(name, result):
    if not result["success"]:
        return f"{name}\t{result['vm_exit_code']}\t0\t-\t-"
    details = result["details"]
    data, balance = native.account_data(from_boc(result["shard_account"]))
    messages = native.outgoing(from_boc(result["transaction"]))
    return "\t".join(
        map(
            str,
            [
                name,
                details["exit"] if details["exit"] is not None else -(2**31),
                (details["action"] or {}).get("code", 0),
                ",".join(m.hash.hex() for m in messages) or "-",
                balance,
                data.hash.hex(),
                str(details["compute_success"]).lower(),
                details["gas"],
                str(details["aborted"]).lower(),
                str(details["action"]["success"]).lower() if details["action"] else "-",
            ],
        )
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chain-config", type=Path)
    parser.add_argument("--genesis-driver", type=Path)
    parser.add_argument("--fee-driver", type=Path)
    parser.add_argument("--preparation-driver", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache-driver", type=Path)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--recovery", action="store_true")
    parser.add_argument("--migration-gate", action="store_true")
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--pop-role", type=int, choices=(1, 2))
    options = parser.parse_args()
    out = options.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    groups = {}
    original = native.Emulator

    class RecordingEmulator(original):
        def _initialize(self, configuration, vm_log_verbosity):
            self.configuration = configuration
            super()._initialize(configuration, vm_log_verbosity)

        def send(self, shard, message):
            result = super().send(shard, message)
            # Admission binary searches use other credits. Only replay the explicit
            # 20,000-credit downstream diagnostic, and report this limited scope.
            if credit(self.configuration) == 20000:
                key = self.configuration.hash.hex()
                group = groups.setdefault(key, [self.configuration, [], []])
                name = f"transaction-{len(group[1]):03d}"
                group[1].append(
                    "\t".join(
                        [
                            name,
                            str(getattr(self, "transaction_time", native.NOW)),
                            str(self.lt),
                            shard.refs[0].boc().hex(),
                            message.boc().hex(),
                            "-",
                        ]
                    )
                )
                group[2].append(transcript(name, result))
            return result

    args = ["test_fee_delivery.py", "--output", str(out / "native")]
    if options.chain_config:
        args += ["--chain-config", str(options.chain_config)]
    else:
        args += ["--credit-probe"]
    if options.genesis_driver:
        args += ["--genesis-driver", str(options.genesis_driver)]
    if options.fee_driver:
        args += ["--fee-driver", str(options.fee_driver)]
    if options.preparation_driver:
        assert options.prepare
        args += ["--preparation-driver", str(options.preparation_driver)]
    if options.cache_driver:
        args += ["--cache-driver", str(options.cache_driver)]
    if options.recovery:
        assert options.prepare
        args += ["--recovery"]
    if options.migration_gate:
        assert options.recovery and options.genesis_driver
        args += ["--migration-gate"]
    if options.prepare:
        args += ["--prepare"]
    if options.pop_role:
        args += ["--pop-role", str(options.pop_role)]
    with patch.object(native, "Emulator", RecordingEmulator), patch.object(sys, "argv", args):
        runpy.run_path(str(ROOT / "test/wallet-v5r2/test_fee_delivery.py"), run_name="__main__")
    assert len(groups) == 1, "unexpected diagnostic configurations"
    configuration, scenarios, expected = next(iter(groups.values()))
    assert len(scenarios) >= 20, "must cover delivery, rejection, boundaries, refund and replay"
    if options.chain_config:
        raw_config = options.chain_config.read_bytes()
        assert from_boc(raw_config).refs[0].hash == configuration.hash
        (out / "config.boc").write_bytes(raw_config)
    else:
        fixture = from_boc((ROOT / "tosctl/src/executor/real_boc/default_config.boc").read_bytes())
        (out / "config.boc").write_bytes(
            Cell().uint(int(fixture.bits, 2), 256).ref(configuration).boc()
        )
    (out / "scenarios.tsv").write_text("\n".join(scenarios) + "\n")
    (out / "native.tsv").write_text("\n".join(expected) + "\n")
    result = subprocess.run(
        [
            str(options.driver.resolve()),
            str(out / "config.boc"),
            str(out / "scenarios.tsv"),
            "18" if options.chain_config else "17",
            "--details",
        ],
        capture_output=True,
        text=True,
    )
    (out / "rust.tsv").write_text(result.stdout)
    (out / "rust.log").write_text(result.stderr)
    assert result.returncode == 0, result.stderr[-2000:]
    observed = result.stdout.splitlines()
    differences = [
        {"native": left, "rust": right} for left, right in zip(expected, observed) if left != right
    ]
    report = {
        "scope": (
            "Full wallet fee delivery with unchanged generated candidate configuration"
            if options.chain_config
            else "Actual transaction parity at diagnostic credit 20000; default admission unpassed"
        ),
        "pop_role": options.pop_role,
        "prepare": options.prepare,
        "recovery": options.recovery,
        "sdk_cache": options.cache_driver is not None,
        "expected_transactions": len(expected),
        "observed_transactions": len(observed),
        "differences": differences,
        "success": len(expected) == len(observed) and not differences,
    }
    (out / "parity.json").write_text(json.dumps(report, indent=2) + "\n")
    assert report["success"], report
    print(json.dumps(report))


if __name__ == "__main__":
    main()
