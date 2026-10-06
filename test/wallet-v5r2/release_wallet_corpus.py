"""Run selected full-wallet fee and recovery flows on unchanged generated config.

The corpus proves recipient execution after recovery and source-transition
sensitivity. It is not the complete worst-case admission or client release gate.
"""

# ruff: noqa: E402
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
from cells import from_boc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--controls", action="store_true")
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    config = args.config.resolve()
    raw = config.read_bytes()
    profiles = [
        ("auth", [], 26),
        ("pop-1", ["--pop-role", "1"], 24),
        ("pop-2", ["--pop-role", "2"], 24),
        ("recovery", ["--prepare", "--recovery"], 64),
    ]
    reports = {}

    def run(name, script, flags):
        command = [
            sys.executable,
            ROOT / "test/wallet-v5r2" / script,
            "--chain-config",
            config,
            "--output",
            out / name,
            *flags,
        ]
        with (out / (name + ".log")).open("w") as log:
            result = subprocess.run(
                list(map(str, command)), cwd=ROOT, stdout=log, stderr=subprocess.STDOUT
            )
        reports[name] = dict(command=list(map(str, command)), exit=result.returncode)
        return result.returncode

    for name, flags, count in profiles:
        if run(name, "fee_tx_parity.py", ["--driver", args.driver.resolve(), *flags]):
            raise RuntimeError("profile failed: " + name)
        folder = out / name
        parity = json.loads((folder / "parity.json").read_text())
        assert parity["success"] and parity["expected_transactions"] == count
        assert parity["observed_transactions"] == count and not parity["differences"]
        assert (folder / "config.boc").read_bytes() == raw
        deliveries = json.loads((folder / "native/results.json").read_text())
        assert deliveries["chain_config_sha256"] == hashlib.sha256(raw).hexdigest()
        assert deliveries["chain_version"] == 18
        if name == "auth":
            assert (
                deliveries["recipient"]["compute_success"]
                and not deliveries["recipient"]["aborted"]
            )
        if name == "recovery":
            recovery = json.loads((folder / "native/recovery-summary.json").read_text())
            assert recovery["recipient_received"] and not recovery["primary_auth_signing_used"]
            assert recovery["primary_pop_signing_used"] and recovery["funded_pop_roles"] == [1, 2]
        successes = []
        scenarios = (folder / "scenarios.tsv").read_text().splitlines()
        receipts = (folder / "native.tsv").read_text().splitlines()
        for scenario, receipt in zip(scenarios, receipts, strict=True):
            message = from_boc(bytes.fromhex(scenario.split("\t")[4]))
            fields = receipt.split("\t")
            if message.bits[:2] == "10" and fields[1] == "0":
                assert fields[6] == "true" and fields[8:] == ["false", "true"]
                successes.append(int(fields[7]))
        assert successes and max(successes) <= 18000, "selected successful fee path exceeds margin"
        reports[name].update(transactions=count, maximum_successful_fee_gas=max(successes))
    if args.controls:
        for transition in ("lock", "migrate"):
            name = "delete-" + transition
            code = run(
                name,
                "test_fee_delivery.py",
                ["--prepare", "--recovery", "--recovery-delete-transition", transition],
            )
            failure = (
                "lock state transition missing"
                if transition == "lock"
                else "migration state transition missing"
            )
            assert code == 1 and failure in (out / (name + ".log")).read_text()
            reports[name]["assertion"] = failure
    assert config.read_bytes() == raw
    report = dict(
        passed=True, config_sha256=hashlib.sha256(raw).hexdigest(), profiles=reports, scope=__doc__
    )
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
