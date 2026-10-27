#!/usr/bin/env python3
"""Regenerate bounded simulation inputs using public deterministic signing keys."""

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "test/wallet-quantum"), str(ROOT / "test/auth-extensions")]
import test_self_pay as wallet  # noqa: E402
from cells import Cell, from_boc  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("func", "fift", "emulator", "mldsa-tool", "slh-tool"):
        parser.add_argument("--" + option, type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    tools = dict(
        FUNC_PATH=args.func,
        FIFT_PATH=args.fift,
        EMULATOR_PATH=args.emulator,
        MLDSA_TOOL=args.mldsa_tool,
        SLH_TOOL=args.slh_tool,
    )
    os.environ.update({key: str(value.resolve()) for key, value in tools.items()})
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="public-self-pay-simulation-") as temporary:
        harness = wallet.Harness(Path(temporary))
        pin = re.search(
            r'"([0-9a-f]{64})"', (ROOT / "crypto/smc-envelope/QuantumSelfPayCode.h").read_text()
        )
        if pin is None or harness.code.hash.hex() != pin.group(1):
            raise RuntimeError("compiled self-pay code differs from the execution profile")
        for role in (1, 2):
            body = harness.message(role=role).refs[0]
            init = wallet.native.state_init(harness.code, harness.data)
            message = (
                Cell()
                .uint(8, 4)
                .addr(harness.address)
                .coins(0)
                .uint(1, 1)
                .uint(1, 1)
                .ref(init)
                .uint(1, 1)
                .ref(body)
            )
            result = harness.transact(
                f"pre-funded-deployment-{role}",
                message,
                account=wallet.uninitialized(harness.address, 100_000_000_000),
            )
            if not result["success"] or result["details"]["exit"] != 0:
                raise RuntimeError("prefunded public fixture did not execute")
        for role, label in ((1, "primary"), (2, "rescue")):
            message = harness.message(role=role)
            result = harness.transact(label, message)
            if not result["success"] or result["details"]["exit"] != 0:
                raise RuntimeError("public role fixture did not execute")
            after = from_boc(result["shard_account"])
            controls = (
                (label + "-replay", message, after, 1804),
                (label + "-forged", harness.message(role=role, forged=True), harness.account, 1808),
                (
                    label + "-domain",
                    harness.message(role=role, context=b"TOS-AUTH-V2-ML-DSA-44-v1"),
                    harness.account,
                    1808,
                ),
            )
            for name, request, account, expected in controls:
                rejected = harness.transact(name, request, account=account)
                if (
                    rejected["success"]
                    or not rejected.get("external_not_accepted")
                    or rejected["vm_exit_code"] != expected
                ):
                    raise RuntimeError("public refusal fixture did not reach its specific code")
        expectations = {}
        for label, mode, count, expected_exit in (
            ("send", 3, 1, 0),
            ("bad-mode", 1, 1, 137),
            ("max-actions", 3, 255, 0),
        ):
            payload = (
                Cell()
                .uint(wallet.TAGS[0], 32)
                .ref(wallet.actions(harness.address, count=count, mode=mode))
            )
            result = harness.transact(label, harness.message(payload=payload))
            if not result["success"] or result["details"]["exit"] != expected_exit:
                raise RuntimeError("public action fixture did not reach its specific outcome")
            expectations[label] = dict(
                balance=str(wallet.native.account_data(from_boc(result["shard_account"]))[1]),
                outputs=len(wallet.native.outgoing(from_boc(result["transaction"]))),
                aborted=result["details"]["aborted"],
                exit_code=expected_exit,
            )
        default_hash = wallet.config().hash.hex()
        if set(harness.parity_groups) != {default_hash}:
            raise RuntimeError("public inputs require exactly the default configuration")
        scenarios = harness.parity_groups[default_hash]["scenarios"]
        if len(scenarios) != 13:
            raise RuntimeError("incomplete public fixture matrix")
        for index, row in enumerate(scenarios):
            columns = row.split("\t")
            if columns[0] in expectations:
                columns[5] = json.dumps(
                    expectations[columns[0]], separators=(",", ":"), sort_keys=True
                )
                scenarios[index] = "\t".join(columns)
        rows = "\n".join(scenarios) + "\n"
        base = from_boc((ROOT / "tosctl/src/executor/real_boc/default_config.boc").read_bytes())
        configuration = Cell(base.bits, [wallet.config()]).boc()
        (output / "scenarios.tsv").write_text(rows)
        (output / "config.boc").write_bytes(configuration)
        provenance = wallet.provenance()
        sources = provenance["sources"]
        for relative in (
            "crypto/fift/lib/Asm.fif",
            "crypto/fift/lib/Fift.fif",
            "crypto/smc-envelope/QuantumSelfPayCode.h",
            "scripts/update-self-pay-simulation-fixtures.py",
        ):
            sources[relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        manifest = dict(
            format="tos-self-pay-simulation-inputs/1",
            code_hash=harness.code.hash.hex(),
            scope="Diagnostic VM16 input fixtures; public seeds11/22, synthetic header/target/prev-blocks in native test. No proofs, phone custody or payment acceptance.",
            sources=sources,
            tools={
                key: hashlib.sha256(path.read_bytes()).hexdigest() for key, path in tools.items()
            },
            files={
                "scenarios.tsv": hashlib.sha256(rows.encode()).hexdigest(),
                "config.boc": hashlib.sha256(configuration).hexdigest(),
            },
            cases=[row.split("\t", 1)[0] for row in scenarios],
        )
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        print("Generated13 bounded public signing input fixtures; exact code profile matched")


if __name__ == "__main__":
    main()
