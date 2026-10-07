#!/usr/bin/env python3
"""Build public-test-only funded Quantum genesis accounts from SDK-generated cells."""

import argparse
import json
import subprocess
from pathlib import Path

from pytosiq_core.boc.deserialize import Boc


def quoted(path):
    return '"' + str(path).replace("\\", "\\\\").replace('"', '\\"') + '"'


def build(fixture_path, build_dir, out):
    fixture = json.loads(fixture_path.read_text())
    if fixture["input"]["global_id"] != 1 or fixture["input"]["network"] != "42" * 32:
        raise ValueError("Only the isolated Quantum candidate namespace is supported")
    out.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[1]
    lines = [
        '"Fift.fif" include',
        '"TosUtil.fif" include',
        '"State.fif" include',
        "0 setworkchain",
        "1 setglobalid",
    ]
    accounts = {}
    roles = [("wallet", 10**15), ("module", 10**12), ("vault", 10**15)]
    if "recipient_init" in fixture["output"]:
        roles.append(("recipient", 10**9))
    for name, balance in roles:
        code = out / (name + "-code.boc")
        data = out / (name + "-data.boc")
        code.write_bytes(bytes.fromhex(fixture["input"][name + "_code"]))
        data.write_bytes(bytes.fromhex(fixture["output"][name + "_data"]))
        roots = Boc(bytes.fromhex(fixture["output"][name + "_init"])).deserialize()
        if len(roots) != 1:
            raise ValueError("SDK StateInit root count")
        expected = roots[0].hash.hex()
        lines.extend(
            [
                quoted(code) + " file>B B>boc",
                quoted(data) + " file>B B>boc",
                f"empty_cell {balance} 0 0 2 register_smc",
                f'0x{expected} = not abort"fixture StateInit address mismatch"',
            ]
        )
        accounts[name] = {"address": "0:" + expected, "balance": balance}
    lines.append('create_state 31 boc+>B "basestate0.boc" B>file')
    script = out / "basechain.fif"
    script.write_text("\n".join(lines) + "\n")
    with (out / "create-state.log").open("w") as log:
        subprocess.run(
            [
                str(build_dir / "crypto/create-state"),
                "-n",
                "-I",
                str(root / "crypto/fift/lib") + ":" + str(root / "crypto/smartcont"),
                "-s",
                str(script),
            ],
            cwd=out,
            stdout=log,
            stderr=subprocess.STDOUT,
            check=True,
            timeout=30,
        )
    (out / "accounts.json").write_text(
        json.dumps(
            {
                "scope": "PUBLIC TEST ONLY; genesis allocation is not a wallet transaction or deployment acceptance",
                "accounts": accounts,
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--sdk-fixture", type=Path)
    inputs.add_argument("--network-input", type=Path, help="Public-test signed transaction export")
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    fixture_path = args.sdk_fixture
    if args.network_input:
        value = json.loads(args.network_input.read_text())
        if set(value["accounts"]) != {"wallet", "module", "vault", "recipient"}:
            raise ValueError("Expected four disposable-network accounts")
        fixture = {"input": {"global_id": value["global_id"], "network": value["network"]}, "output": {}}
        for role, account in value["accounts"].items():
            roots = Boc(bytes.fromhex(account["state_init"])).deserialize()
            if len(roots) != 1 or account["address"] != "0:" + roots[0].hash.hex():
                raise ValueError("Exported account address mismatch")
            fixture["input"][role + "_code"] = account["code"]
            fixture["output"][role + "_data"] = account["data"]
            fixture["output"][role + "_init"] = account["state_init"]
        # Keep adaptation outside the generated directory (build requires it fresh).
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            fixture_path = Path(temporary) / "fixture.json"
            fixture_path.write_text(json.dumps(fixture))
            build(fixture_path, args.build_dir.resolve(), args.out.resolve())
    else:
        build(fixture_path.resolve(), args.build_dir.resolve(), args.out.resolve())
