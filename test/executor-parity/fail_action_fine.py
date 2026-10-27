"""Both executors must collect the fines of sent messages when a later action fails.

From global version 15 a failed action phase is fined for every message that
was already sent in it, not only for the action that failed. The probe sends one
message (bodies of 1, 2, 5 and 9 cells) and then requests a reservation no
account can cover, so the action phase fails with 37 after one successful send. Whole
transactions are run in the native emulator and in the Rust executor
(pq-tx-parity --details) at versions 14, 15 and 16; the two must agree
exactly, and the account must pay more at 15 and 16 than at 14.

Usage: fail_action_fine.py --driver <pq-tx-parity> --output <dir>
Needs FUNC_PATH, FIFT_PATH and EMULATOR_PATH like the other native harnesses.
"""

# ruff: noqa: E402
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "test/auth-extensions"), str(ROOT / "test/wallet-quantum")]
import native
from cells import Cell, from_boc
from fee_tx_parity import transcript
from transaction_roots import compare as compare_roots

VERSIONS = (14, 15, 16)
PROBE = (0, 0x5151)
PAYEE = (0, 0x7777)
NOT_ENOUGH_FUNDS = 37


def outbound_message(depth):
    body = Cell().uint(0xAB, 8)
    for index in range(depth):
        body = Cell().uint(index, 8).ref(body)
    return (
        Cell()
        .uint(0, 1)  # int_msg_info
        .uint(1, 1)  # ihr_disabled
        .uint(0, 1)  # bounce
        .uint(0, 1)  # bounced
        .uint(0, 2)  # src: addr_none, filled in by the executor
        .addr(PAYEE)
        # Enough value for the fine to be computed over every cell of the body.
        .coins(1_000_000_000)
        .uint(0, 1)  # no extra currencies
        .coins(0)
        .coins(0)
        .uint(0, 64)
        .uint(0, 32)
        .uint(0, 1)  # no StateInit
        .uint(1, 1)  # body in a reference
        .ref(body)
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    code = native.compile_contract(
        str(Path(__file__).with_name("fail-action-fine.fc").resolve()), out / "probe.boc"
    )
    cases = [
        (f"depth{depth}", native.active_account(PROBE, code, Cell().ref(outbound_message(depth))))
        for depth in (0, 1, 4, 8)
    ]
    message = native.internal(PAYEE, PROBE, Cell().uint(1, 32))
    fixture = from_boc((ROOT / "tosctl/src/executor/real_boc/default_config.boc").read_bytes())
    report, balances, failures = {}, {}, []
    for version in VERSIONS:
        native_rows, scenarios, roots = [], [], []
        emulator = native.Emulator(version)
        try:
            for name, shard in cases:
                result = emulator.send(shard, message)
                assert result["success"], f"v{version} {name}: emulator error, not a transaction"
                details = result["details"]
                action = details["action"] or {}
                if details["exit"] != 0 or action.get("code") != NOT_ENOUGH_FUNDS:
                    failures.append(f"v{version} {name}: the probe did not fail its second action")
                native_rows.append(transcript(name, result))
                _, balance = native.account_data(from_boc(result["shard_account"]))
                balances.setdefault(name, {})[version] = balance
                scenarios.append(
                    "\t".join(
                        [
                            name,
                            str(native.NOW),
                            str(emulator.lt),
                            shard.refs[0].boc().hex(),
                            message.boc().hex(),
                            "-",
                        ]
                    )
                )
                if version == 16:
                    # Full original wrapper and the constructor's explicit
                    # deterministic defaults, separate from the native oracle.
                    roots.append(
                        (
                            "\t".join(
                                [
                                    name,
                                    str(native.NOW),
                                    str(emulator.lt),
                                    shard.boc().hex(),
                                    message.boc().hex(),
                                    "0" * 64,
                                    "-",
                                    "-",
                                    "0",
                                ]
                            ),
                            result,
                        )
                    )
        finally:
            emulator.close()
        (out / f"v{version}.tsv").write_text("\n".join(scenarios) + "\n")
        config = out / f"v{version}-config.boc"
        config.write_bytes(Cell().uint(int(fixture.bits, 2), 256).ref(native.config(version)).boc())
        command = [
            str(args.driver.resolve()),
            str(config),
            str(out / f"v{version}.tsv"),
            str(version),
            "--details",
        ]
        rust = subprocess.run(command, capture_output=True, text=True)
        if rust.returncode != 0:
            raise SystemExit(f"v{version}: rust driver failed: {rust.stderr.strip()[-400:]}")
        rust_rows = rust.stdout.splitlines()
        for native_row, rust_row in zip(native_rows, rust_rows, strict=True):
            if rust_row != native_row:
                failures.append(
                    f"v{version}: executors differ\n  native {native_row}\n  rust   {rust_row}"
                )
        report[version] = {"native": native_rows, "rust": rust_rows}
        if version == 16:
            report[version]["root_rows"] = compare_roots(
                args.driver, config, roots, out, f"v{version}"
            )
    for name, by_version in balances.items():
        if not by_version[15] < by_version[14]:
            failures.append(f"{name}: no fine for the sent message at 15: {by_version}")
        if by_version[15] != by_version[16]:
            failures.append(f"{name}: versions 15 and 16 differ: {by_version}")
    summary = {
        "passed": not failures,
        "balances": balances,
        "fine_from_15": {name: v[14] - v[15] for name, v in balances.items()},
        "rows": report,
        "failures": failures,
    }
    (out / "result.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({k: summary[k] for k in ("passed", "balances", "fine_from_15", "failures")}))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
