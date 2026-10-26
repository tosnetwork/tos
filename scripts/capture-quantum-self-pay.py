#!/usr/bin/env python3
"""Capture native-verified self-pay account proofs on a fresh disposable chain."""

import argparse
import asyncio
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

from quantum_self_pay_fixture import GLOBAL_ID, NAMESPACE, ROOT, build_fixture, one_cell, require


def stop_process_group(process, grace=5.0):
    """Reclaim children even if their group leader has already crashed."""

    def exists():
        try:
            os.killpg(process.pid, 0)
            return True
        except ProcessLookupError:
            return False

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
        if not exists():
            break
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            break
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            process.poll()  # Reap the leader while waiting for the remaining children.
            if not exists():
                break
            time.sleep(0.05)
    process.wait(timeout=grace)
    require(not exists(), "owned network process group did not exit")


async def serve(build, workdir, basechain):
    """Read-only chain: no faucet or native wallet-client connection is needed."""
    from tostester.install import Install
    from tostester.network import Network, StartOptions
    from tostester.pq_initial_validator import make_deterministic_pq_initial_validator
    from tostester.zerostate import basechain_fixture_balance

    require(not workdir.exists(), "fresh network directory required")
    workdir.mkdir(parents=True)
    encoded = basechain.read_bytes()
    basechain_fixture_balance(encoded, GLOBAL_ID)
    async with Network(Install(build, ROOT), workdir, base_port=39000) as network:
        network.config.global_version = 16
        network.config.global_id = GLOBAL_ID
        network.config.auth_network_tag = NAMESPACE
        network.config.deployment_fee_schedule = True
        network.config.quantum_admission_candidate = True
        network.config.basechain_fixture = encoded
        dht = network.create_dht_node()
        node = network.create_full_node()
        make_deterministic_pq_initial_validator(node, 0)
        node.announce_to(dht)
        (workdir / "lite-client.json").write_text(node.liteserver_config.to_json())
        await dht.run()
        await node.run(StartOptions(args=["--json-rpc-address", "127.0.0.1:38545"]))
        await asyncio.Event().wait()


def basechain_ready(response):
    """Readiness only: every basechain shard must have a non-zerostate block."""
    shards = [
        shard
        for shard in response.get("result", {}).get("shards", [])
        if shard.get("workchain") == 0
    ]
    return bool(shards) and all(shard.get("seqno", 0) > 0 for shard in shards)


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
    for name, selected_anchor, selected_material, expected_reason in [
        ("genuine", anchor, material, None),
        (
            "wrong-anchor",
            wrong_anchor,
            material,
            "proof chain does not start at the authenticated block",
        ),
        ("missing-account", anchor, missing, "account proof is missing"),
    ]:
        accepted = expected_reason is None
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
            and value["status"] == ("verified" if accepted else "refused")
            and value.get("reason") == expected_reason,
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
        str(Path(__file__).resolve()),
        "--serve",
        "--build-dir",
        str(build),
        "--input",
        str(out / "genesis/basestate0.boc"),
        "--out",
        str(network),
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
                require(
                    process.poll() is None, f"node exited before readiness: {process.returncode}"
                )
                try:
                    request = urllib.request.Request(
                        "http://127.0.0.1:38545/jsonRPC",
                        data=json.dumps(
                            {
                                "jsonrpc": "2.0",
                                "id": 1,
                                "method": "getShards",
                                "params": {},
                            }
                        ).encode(),
                        headers={"Content-Type": "application/json"},
                    )
                    with urllib.request.urlopen(request, timeout=1) as response:
                        result = json.load(response)
                        if basechain_ready(result):
                            (out / "readiness.json").write_text(json.dumps(result) + "\n")
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
            stop_process_group(process)
            (out / "network-exit.json").write_text(json.dumps({"exit": process.returncode}) + "\n")


if __name__ == "__main__":

    def interrupted(_signal, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument(
        "--input", required=True, type=Path, help="Public vectors or frozen genesis fixture"
    )
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--serve", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.serve:
        asyncio.run(serve(args.build_dir.resolve(), args.out.resolve(), args.input.resolve()))
    else:
        capture(args.build_dir.resolve(), args.input.resolve(), args.out.resolve())
