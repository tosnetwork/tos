#!/usr/bin/env python3
"""Boot a fresh disposable PQ candidate and read back config; never sign wallet traffic."""

import argparse
import base64
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from pytosiq_core.boc.deserialize import Boc
from pytosiq_core.tlb.config import ConfigParam20, ConfigParam21


def require(value, message):
    if not value:
        raise ValueError(message)


def rpc(endpoint, index):
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": index, "method": "getConfigParam", "params": {"param": index}}
    ).encode()
    request = urllib.request.Request(
        endpoint, data=payload, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        value = json.load(response)
    require(value.get("id") == index and value.get("ok") is True, "config query refused")
    raw = base64.b64decode(value["result"]["config"]["bytes"], validate=True)
    roots = Boc(raw).deserialize()
    require(len(roots) == 1, "config BOC root count")
    return roots[0]


def validate(cells):
    version = cells[8].begin_parse()
    require(
        version.load_uint(8) == 0xC4 and version.load_uint(32) == 18,
        "candidate VM version mismatch",
    )
    version.load_uint(64)
    require(version.remaining_bits == 0 and version.remaining_refs == 0, "version trailing data")
    identity = cells[19].begin_parse()
    require(
        identity.load_int(32) == 1
        and identity.remaining_bits == 0
        and identity.remaining_refs == 0,
        "candidate global ID mismatch",
    )
    policy = cells[48].begin_parse()
    require(
        policy.load_uint(8) == 0xA1 and policy.load_bytes(32) == bytes.fromhex("42" * 32),
        "candidate AUTH namespace mismatch",
    )
    gas = {}
    for index, decoder, expected_credit in [(20, ConfigParam20, 10000), (21, ConfigParam21, 20000)]:
        source = cells[index].begin_parse()
        decoded = decoder.deserialize(source)
        require(source.remaining_bits == 0 and source.remaining_refs == 0, "gas trailing data")
        while decoded.other is not None:
            decoded = decoded.other
        require(decoded.gas_credit == expected_credit, "candidate gas credit mismatch")
        gas[str(index)] = {
            name: getattr(decoded, name)
            for name in (
                "gas_price",
                "gas_limit",
                "special_gas_limit",
                "gas_credit",
                "block_gas_limit",
            )
        }
    require(
        gas["21"]["gas_price"] == 436907
        and gas["21"]["gas_limit"] == 30000000
        and gas["21"]["special_gas_limit"] == 30000000
        and gas["21"]["block_gas_limit"] == 60000000,
        "basechain candidate tariff mismatch",
    )
    require(
        gas["20"]["gas_price"] == 655360000
        and gas["20"]["gas_limit"] == 1000000
        and gas["20"]["special_gas_limit"] == 70000000
        and gas["20"]["block_gas_limit"] == 2500000,
        "masterchain candidate tariff mismatch",
    )
    return gas


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    network = out / "network"
    require(not network.exists(), "fresh owned network directory required")
    env = os.environ.copy()
    env["TOS_BUILD_DIR"] = str(args.build_dir.resolve())
    env["PYTHONPATH"] = str(root / "test/tostester/src")
    env["PYTHONUNBUFFERED"] = "1"
    env.pop("TOS_GLOBAL_VERSION", None)
    env.pop("TOS_AUTH_NETWORK_TAG", None)
    command = [
        sys.executable,
        str(root / "scripts/localnet-jsonrpc.py"),
        "--v5r2-admission-candidate",
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
    log = out / "network.log"
    with log.open("w") as stream:
        process = subprocess.Popen(
            command,
            cwd=root,
            env=env,
            stdout=stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 200
            while True:
                require(process.poll() is None, "candidate node exited before readiness")
                try:
                    with urllib.request.urlopen(
                        "http://127.0.0.1:38745/readyz", timeout=1
                    ) as response:
                        ready = json.load(response).get("ok") is True
                except Exception:
                    ready = False
                if ready:
                    break
                require(time.monotonic() < deadline, "candidate boot deadline exceeded")
                time.sleep(1)
            cells = {
                index: rpc("http://127.0.0.1:38545/jsonRPC", index) for index in (8, 19, 20, 21, 48)
            }
            gas = validate(cells)
            report = {
                "scope": "Disposable candidate boot/config readback only, no wallet signature or lifecycle acceptance",
                "source": subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], cwd=root, text=True
                ).strip(),
                "config_hashes": {str(k): v.hash.hex() for k, v in cells.items()},
                "gas": gas,
                "binaries": {
                    name: hashlib.sha256((args.build_dir / name / name).read_bytes()).hexdigest()
                    for name in ("validator-engine", "dht-server")
                },
            }
            (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            print("Candidate PQ block readiness and exact configured fields pass", flush=True)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGINT)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=10)


if __name__ == "__main__":
    main()
