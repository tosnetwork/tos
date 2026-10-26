#!/usr/bin/env python3
"""Capture native-verified self-pay account proofs on a fresh disposable chain."""

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from quantum_self_pay_fixture import ROOT, build_fixture, one_cell, require


def validate_account(value, record, code_hash):
    account = value["account"]
    require(account["address"] == record["address"], "account address mismatch")
    if record["status"] == "absent":
        require(account["exists"] is False, "expected proven absence")
        return
    require(
        account["exists"] is True and account["balance"] == str(record["balance"]),
        "account allocation mismatch",
    )
    if record["status"] == "active":
        require(
            account["active"] is True
            and account["code_hash"] == code_hash
            and account["data_hash"] == record["data_hash"],
            "active identity mismatch",
        )
        return
    require(account["active"] is False, "prefunded account already active")
    s = one_cell(base64.b64decode(account["state_boc"], validate=True)).begin_parse()
    require(
        s.load_bit() == 1 and s.load_address().to_str(is_user_friendly=False) == record["address"],
        "prefunded account envelope",
    )
    for _ in range(2):
        length = s.load_uint(3)
        require(length < 7, "storage statistic length")
        s.skip_bits(length * 8)
    extra = s.load_uint(3)
    require(extra in (0, 1), "storage extra tag")
    if extra:
        s.skip_bits(256)
    s.skip_bits(32)
    if s.load_bit():
        s.load_coins()
    s.skip_bits(64)
    require(s.load_coins() == record["balance"], "prefunded raw balance mismatch")
    require(s.load_bit() == 0, "unexpected extra currency")
    require(
        s.load_uint(2) == 0 and s.remaining_bits == 0 and s.remaining_refs == 0,
        "expected uninitialized account, not frozen or active",
    )


def proof_controls(verifier, public, out):
    """First replay the genuine proof, then require two deliberate corruptions to refuse."""
    controls = out / "controls"
    controls.mkdir()
    anchor = public / "anchor.json"
    wrong = json.loads(anchor.read_text())
    wrong["root_hash"] = f"{int(wrong['root_hash'], 16) ^ 1:064x}"
    wrong_anchor = controls / "wrong-anchor.json"
    wrong_anchor.write_text(json.dumps(wrong) + "\n")
    material = public / "active/material"
    missing = controls / "missing-account"
    shutil.copytree(material, missing)
    (missing / "account.tl").unlink()
    rows = {}
    for name, selected_anchor, selected_material, accepted in [
        ("genuine", anchor, material, True),
        ("wrong-anchor", wrong_anchor, material, False),
        ("missing-account", anchor, missing, False),
    ]:
        result = subprocess.run(
            [
                str(verifier),
                "verify",
                "--anchor",
                str(selected_anchor),
                "--request",
                str(public / "active/request.json"),
                "--material",
                str(selected_material),
                "--state",
                str(controls / (name + "-state.json")),
            ],
            capture_output=True,
            timeout=30,
        )
        (controls / (name + "-result.json")).write_bytes(result.stdout)
        (controls / (name + ".log")).write_bytes(result.stderr)
        value = json.loads(result.stdout)
        require(
            result.returncode == (0 if accepted else 1)
            and value["status"] == ("verified" if accepted else "refused"),
            f"native proof control failed: {name}",
        )
        rows[name] = {
            "exit": result.returncode,
            "status": value["status"],
            "reason": value.get("reason"),
        }
    (out / "proof-controls.json").write_text(json.dumps(rows, indent=2) + "\n")
    return rows


def capture(build, public_input, out):
    require(not out.exists(), "fresh capture output required")
    out.mkdir(parents=True)
    fixture = build_fixture(public_input, build, out / "genesis")
    network = out / "network"
    env = dict(
        os.environ,
        TOS_BUILD_DIR=str(build),
        PYTHONPATH=str(ROOT / "test/tostester/src"),
        PYTHONUNBUFFERED="1",
    )
    env.pop("TOS_GLOBAL_VERSION", None)
    env.pop("TOS_AUTH_NETWORK_TAG", None)
    command = [
        sys.executable,
        str(ROOT / "scripts/localnet-jsonrpc.py"),
        "--quantum-admission-candidate",
        "--basechain-fixture",
        str(out / "genesis/basestate0.boc"),
        "--workdir",
        str(network),
        "--rpc",
        "127.0.0.1:38545",
        "--control",
        "127.0.0.1:38745",
        "--base-port",
        "39000",
        "--boot-timeout",
        "180",
    ]
    verifier = build / "lite-client/proof-verify/tos-proof-verify"
    public = out / "mobile-fixture"
    public.mkdir()
    shutil.copyfile(
        out / "genesis/public-self-pay-accounts.json", public / "public-self-pay-accounts.json"
    )
    with (out / "network.log").open("w") as log:
        process = subprocess.Popen(
            command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True
        )
        try:
            deadline = time.monotonic() + 200
            while True:
                require(process.poll() is None, "node exited before readiness")
                try:
                    with urllib.request.urlopen(
                        "http://127.0.0.1:38745/readyz", timeout=1
                    ) as response:
                        if json.load(response).get("ok") is True:
                            break
                except (OSError, ValueError):
                    pass
                require(time.monotonic() < deadline, "node readiness deadline exceeded")
                time.sleep(1)
            anchor = public / "anchor.json"
            anchor.write_bytes(
                subprocess.check_output(
                    [
                        str(verifier),
                        "anchor",
                        "--zerostate",
                        str(network / "state/zerostate.boc"),
                    ],
                    cwd=ROOT,
                    timeout=20,
                )
            )
            reads = {}
            target = None
            for name in ("policy", "active", "prefunded", "absent"):
                directory = public / name
                directory.mkdir()
                request = {"mode": "live", "max_age_seconds": 300}
                if name == "policy":
                    request["config_params"] = [8, 19, 20, 21, 48]
                else:
                    request.update(target=target, account=fixture["accounts"][name]["address"])
                path = directory / "request.json"
                encoded = (json.dumps(request) + "\n").encode()
                path.write_bytes(encoded)
                result = subprocess.run(
                    [
                        str(verifier),
                        "verify",
                        "--anchor",
                        str(anchor),
                        "--request",
                        str(path),
                        "--liteserver",
                        str(network / "lite-client.json"),
                        "--state",
                        str(out / "live-state.json"),
                        "--save-material",
                        str(directory / "material"),
                        "--timeout-seconds",
                        "45",
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    timeout=60,
                )
                (out / (name + "-result.json")).write_bytes(result.stdout)
                (out / (name + "-verifier.log")).write_bytes(result.stderr)
                require(result.returncode == 0, f"native {name} proof refused")
                value = json.loads(result.stdout)
                require(
                    value["status"] == "verified"
                    and value["mode"] == "live"
                    and value["interface"] == "tos-proof-verify/1"
                    and value["anchor"] == json.loads(anchor.read_text())
                    and value["request_sha256"] == hashlib.sha256(encoded).hexdigest(),
                    "native proof binding mismatch",
                )
                point = {
                    key: value["target"][key]
                    for key in ("workchain", "shard", "seqno", "root_hash", "file_hash")
                }
                if target is None:
                    target = point
                require(point == target, "proof checkpoint mismatch")
                if name != "policy":
                    validate_account(value, fixture["accounts"][name], fixture["wallet_code_hash"])
                else:
                    # Reuse the exact candidate config/tariff validation against
                    # authenticated cells, never against unauthenticated RPC JSON.
                    import importlib.util

                    spec = importlib.util.spec_from_file_location(
                        "candidate", ROOT / "scripts/check-quantum-candidate-network.py"
                    )
                    candidate = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(candidate)
                    cells = {
                        entry["index"]: one_cell(base64.b64decode(entry["boc"], validate=True))
                        for entry in value["config_params"]
                    }
                    candidate.validate(cells)
                for file in (directory / "material").iterdir():
                    require(
                        file.is_file()
                        and not file.is_symlink()
                        and re.fullmatch(
                            r"(?:masterchain-info|config|account|exec-config|libraries|chain-\d{4}|descent-\d{4})\.tl",
                            file.name,
                        )
                        is not None,
                        "unexpected material file",
                    )
                reads[name] = value
            controls = proof_controls(verifier, public, out)
            files = {}
            for file in sorted(public.rglob("*")):
                if file.is_file():
                    files[str(file.relative_to(public))] = {
                        "bytes": file.stat().st_size,
                        "sha256": hashlib.sha256(file.read_bytes()).hexdigest(),
                    }
            manifest = {
                "scope": "PUBLIC TEST: native-verified self-pay genesis states at controlled time; not deployment, signing, custody or current-live acceptance",
                "controlled_now": max(value["live"]["now"] for value in reads.values()),
                "target": target,
                "proof_controls": controls,
                "files": files,
                "capture_source_commit": subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
                ).strip(),
                "capture_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "binaries": {
                    name: hashlib.sha256((build / name).read_bytes()).hexdigest()
                    for name in (
                        "validator-engine/validator-engine",
                        "dht-server/dht-server",
                        "lite-client/proof-verify/tos-proof-verify",
                    )
                },
            }
            (public / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
            print("Self-pay active, prefunded and absent native proofs captured", flush=True)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGINT)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=10)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument(
        "--input", required=True, type=Path, help="Public vectors or frozen genesis fixture"
    )
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    capture(args.build_dir.resolve(), args.input.resolve(), args.out.resolve())
