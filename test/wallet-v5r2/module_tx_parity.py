"""Replay actual PQ module, wallet and recipient transactions in both executors."""

import argparse
import hashlib
import json
import runpy
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

from fee_tx_parity import Cell, from_boc, native, transcript


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-signer", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--chain-config", type=Path, help="Use the unchanged generated version-18 ConfigParams"
    )
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    groups = {}
    original = native.Emulator

    class RecordingEmulator(original):
        def _initialize(self, configuration, vm_log_verbosity):
            self.configuration = configuration
            super()._initialize(configuration, vm_log_verbosity)

        def send(self, shard, message):
            result = super().send(shard, message)
            group = groups.setdefault(self.configuration.hash.hex(), [self.configuration, [], []])
            name = f"transaction-{len(group[1]):03d}"
            group[1].append(
                "\t".join(
                    [
                        name,
                        str(native.NOW),
                        str(self.lt),
                        shard.refs[0].boc().hex(),
                        message.boc().hex(),
                        "-",
                    ]
                )
            )
            group[2].append(transcript(name, result))
            return result

    argv = [
        "test_module_delivery.py",
        "--native-signer",
        str(args.native_signer.resolve()),
        "--output",
        str(out / "native"),
    ]
    if args.chain_config:
        argv += ["--chain-config", str(args.chain_config.resolve())]
    with patch.object(native, "Emulator", RecordingEmulator), patch.object(sys, "argv", argv):
        runpy.run_path(
            str(Path(__file__).with_name("test_module_delivery.py")), run_name="__main__"
        )
    assert len(groups) == 2, "must exercise active and retired global policy"
    if args.chain_config:
        raw = args.chain_config.read_bytes()
        root = from_boc(raw)
        assert root.refs[0].hash.hex() in groups, (
            "the actual candidate configuration was not executed"
        )
        module_results = json.loads((out / "native/results.json").read_text())
        assert module_results["chain_config_sha256"] == hashlib.sha256(raw).hexdigest()
        assert module_results["chain_version"] == 18
    else:
        raw = None
        root = from_boc(
            (native.ROOT / "tosctl/src/executor/real_boc/default_config.boc").read_bytes()
        )
    reports = []
    for index, (configuration, scenarios, expected) in enumerate(groups.values()):
        folder = out / f"configuration-{index}"
        folder.mkdir()
        generated = raw is not None and configuration.hash == root.refs[0].hash
        (folder / "config.boc").write_bytes(
            raw if generated else Cell(bits=root.bits, refs=[configuration]).boc()
        )
        (folder / "scenarios.tsv").write_text("\n".join(scenarios) + "\n")
        (folder / "native.tsv").write_text("\n".join(expected) + "\n")
        result = subprocess.run(
            [
                str(args.driver.resolve()),
                str(folder / "config.boc"),
                str(folder / "scenarios.tsv"),
                "18" if args.chain_config else "17",
                "--details",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        (folder / "rust.tsv").write_text(result.stdout)
        (folder / "rust.log").write_text(result.stderr)
        assert result.returncode == 0, result.stderr[-3000:]
        actual = result.stdout.splitlines()
        assert len(actual) == len(expected), "missing executor receipts"
        differences = [
            {"native": a, "rust": b} for a, b in zip(expected, actual, strict=True) if a != b
        ]
        reports.append(
            {
                "configuration": configuration.hash.hex(),
                "transactions": len(expected),
                "differences": differences,
                "profile": "unchanged-generated-candidate"
                if generated
                else "retirement-control"
                if args.chain_config
                else "diagnostic",
            }
        )
    (out / "parity.json").write_text(
        json.dumps(
            {
                "scope": __doc__,
                "groups": reports,
                "generated_config_sha256": hashlib.sha256(raw).hexdigest() if raw else None,
            },
            indent=2,
        )
        + "\n"
    )
    assert all(not report["differences"] for report in reports), reports
    control = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).with_name("test_module_delivery.py")),
            "--native-signer",
            str(args.native_signer.resolve()),
            "--delete-recipient-update",
            "--output",
            str(out / "recipient-control"),
            *(["--chain-config", str(args.chain_config.resolve())] if args.chain_config else []),
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    log = control.stdout + control.stderr
    (out / "recipient-control.log").write_text(log)
    assert control.returncode != 0 and "AssertionError: recipient state update missing" in log, log[
        -3000:
    ]
    (out / "recipient-control.json").write_text(
        json.dumps(
            {
                "exit": control.returncode,
                "failure": "recipient state update missing",
                "scope": "Removing recipient update preserves successful execution but fails delivery assertion",
            },
            indent=2,
        )
        + "\n"
    )
    if args.chain_config:
        assert args.chain_config.read_bytes() == raw
    print(
        f"{sum(report['transactions'] for report in reports)} module/wallet/recipient transactions match"
    )


if __name__ == "__main__":
    main()
