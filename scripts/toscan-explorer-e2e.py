#!/usr/bin/env python3
# Copyright (C) 2025-2026 TOS Network.
"""Release-gate the TOSCAN data path against a real local TOS chain.

This test starts a native validator, the read-only ``tosctl explorer``
profile, and the real Agent Economy seed. It verifies route isolation,
canonical indexing, rich transaction/message data, contract discovery, and
durable recovery after restarting the explorer process.
"""

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DEFAULT_WORKDIR = REPO / "test/integration/.toscan-explorer-e2e"
CONTRACT_KINDS = {
    "agent_account",
    "capability_registry",
    "service_actor",
    "task_escrow",
    "dispute",
}


def request_json(url: str, body=None, timeout=15):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        raw = error.read()
        return error.code, json.loads(raw.decode()) if raw else {}


def wait_until(label: str, predicate, timeout=180):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                print(f"PASS: {label}")
                return value
        except Exception as error:  # endpoint can be absent during startup
            last_error = error
        time.sleep(1)
    raise TimeoutError(f"{label} timed out: {last_error}")


def start(command: list[str], cwd: Path, log_path: Path, env=None):
    output = log_path.open("ab")
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdout=output,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    process._toscan_log = output  # type: ignore[attr-defined]
    return process


def stop(process):
    if process is None:
        return
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
    process._toscan_log.close()  # type: ignore[attr-defined]


def generate_explorer_config(tosctl: Path, path: Path, rpc_origin: str, http_bind: str):
    subprocess.run(
        [str(tosctl), "config", "generate", "-o", str(path), "--force"],
        cwd=REPO,
        check=True,
    )
    config = json.loads(path.read_text())
    config["chain_rpc"] = {"urls": [f"{rpc_origin}/"], "api_key": None}
    config["http"] = {"bind": http_bind, "enable_swagger": False, "auth": None}
    config["master_wallet"] = None
    config["elections"] = None
    config["voting"] = None
    config["tick_interval"] = 1
    config["log"] = None
    path.write_text(json.dumps(config, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workdir", default=str(DEFAULT_WORKDIR))
    parser.add_argument("--tosctl", default=str(REPO / "tosctl/src/target/debug/tosctl"))
    parser.add_argument("--rpc-port", type=int, default=19451)
    parser.add_argument("--control-port", type=int, default=19452)
    parser.add_argument("--explorer-port", type=int, default=19453)
    parser.add_argument("--base-port", type=int, default=26900)
    args = parser.parse_args()

    workdir = Path(args.workdir).resolve()
    tosctl = Path(args.tosctl).resolve()
    if not tosctl.exists():
        parser.error(f"tosctl binary not found: {tosctl}")
    shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True)
    rpc_origin = f"http://127.0.0.1:{args.rpc_port}"
    control_origin = f"http://127.0.0.1:{args.control_port}"
    explorer_origin = f"http://127.0.0.1:{args.explorer_port}"
    config = workdir / "tosctl-explorer.json"
    manifest = workdir / "seed-manifest.json"
    node = explorer = None

    try:
        node = start(
            [
                sys.executable,
                str(REPO / "scripts/localnet-jsonrpc.py"),
                "--rpc",
                f"127.0.0.1:{args.rpc_port}",
                "--control",
                f"127.0.0.1:{args.control_port}",
                "--validators",
                "1",
                "--workdir",
                str(workdir / "localnet"),
                "--base-port",
                str(args.base_port),
            ],
            REPO,
            workdir / "node.log",
        )
        wait_until(
            "native localnet ready",
            lambda: request_json(f"{control_origin}/readyz")[0] == 200,
        )

        generate_explorer_config(
            tosctl,
            config,
            rpc_origin,
            f"127.0.0.1:{args.explorer_port}",
        )
        explorer = start(
            [str(tosctl), "explorer", "-c", str(config)],
            REPO,
            workdir / "explorer.log",
        )
        wait_until(
            "explorer-only HTTP ready",
            lambda: request_json(f"{explorer_origin}/health")[0] == 200,
            timeout=45,
        )

        subprocess.run(
            [
                sys.executable,
                str(REPO / "scripts/toscan-dev-seed.py"),
                "--rpc",
                rpc_origin,
                "--control",
                control_origin,
                "--config",
                str(workdir / "seed-config.json"),
                "--manifest",
                str(manifest),
                "--tosctl",
                str(tosctl),
            ],
            cwd=REPO,
            check=True,
        )
        seed = json.loads(manifest.read_text())
        assert set(seed["addresses"]) == CONTRACT_KINDS
        print("PASS: five real Agent Economy contracts deployed")

        for path in ("/auth/login", "/v1/elections", "/swagger", "/openapi.json"):
            status, _ = request_json(f"{explorer_origin}{path}")
            assert status == 404, f"explorer-only route leaked: {path} returned {status}"
        print("PASS: operator, auth and documentation routes are absent")

        def all_contracts_visible():
            for kind, address in seed["addresses"].items():
                encoded = urllib.parse.quote(address, safe=":")
                status, body = request_json(
                    f"{explorer_origin}/explorer/contracts/{kind}/{encoded}"
                )
                if status != 200 or body.get("result", {}).get("address") != address:
                    return False
            return True

        wait_until("all seeded contracts discovered chain-wide", all_contracts_visible, timeout=180)

        rich = None

        def rich_transaction_visible():
            nonlocal rich
            status, body = request_json(
                f"{explorer_origin}/explorer/transactions?offset=0&limit=200"
            )
            if status != 200:
                return False
            rich = next(
                (
                    item
                    for item in body.get("result", [])
                    if item.get("fee") is not None and item.get("in_msg_hash")
                ),
                None,
            )
            return rich

        wait_until("indexed transaction carries fee and inbound-message hash", rich_transaction_visible)
        assert rich is not None
        status, raw = request_json(
            f"{rpc_origin}/jsonRPC",
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getTransactions",
                "params": {
                    "address": rich["account"],
                    "limit": 1,
                    "lt": rich["lt"],
                    "hash": rich["hash"],
                },
            },
        )
        transaction = raw.get("result", [None])[0]
        assert status == 200 and transaction
        assert transaction.get("fee") is not None
        assert isinstance(transaction.get("in_msg"), dict)
        assert isinstance(transaction.get("out_msgs"), list)
        print("PASS: node returns structured transaction message flow")

        before = request_json(f"{explorer_origin}/explorer/status")[1]["result"]
        stop(explorer)
        explorer = start(
            [str(tosctl), "explorer", "-c", str(config)],
            REPO,
            workdir / "explorer-restart.log",
        )
        wait_until(
            "explorer restarts against the durable index",
            lambda: request_json(f"{explorer_origin}/health")[0] == 200,
            timeout=45,
        )
        after = request_json(f"{explorer_origin}/explorer/status")[1]["result"]
        assert after["blocks"] >= before["blocks"]
        assert after["transactions"] >= before["transactions"]
        assert after["contracts"] == before["contracts"] == 5
        print("PASS: restart preserves block, transaction and contract discovery")
        print("TOSCAN REAL-CHAIN GATE: PASS")
    except Exception:
        for name in ("node.log", "explorer.log", "explorer-restart.log"):
            path = workdir / name
            if path.exists():
                print(f"\n--- {name} (tail) ---", file=sys.stderr)
                print("".join(path.read_text(errors="replace").splitlines(True)[-80:]), file=sys.stderr)
        raise
    finally:
        stop(explorer)
        stop(node)


if __name__ == "__main__":
    main()
