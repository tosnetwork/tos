#!/usr/bin/env python3
"""Retain the advertised localnet JSON-RPC demo and TOSCAN route, serially.

The resident demo's ``changed=TIMEOUT`` is not a process failure. This outer
verifier checks the actual JSON-RPC bodies and bounds shutdown independently.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error

REPO = Path(__file__).resolve().parents[1]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rpc(rpc_addr, method, **params):
    body = json.dumps({"jsonrpc": "2.0", "id": method, "method": method, "params": params}).encode()
    url = f"http://{rpc_addr}/jsonRPC"
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            status, raw = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, raw = error.code, error.read()
    return {"url": url, "request_body": body.decode(), "status": status,
            "response_body": raw.decode()}


def wait_for_log(path, pattern, process, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        match = re.search(pattern, path.read_text(errors="replace") if path.exists() else "")
        if match:
            return match
        if process.poll() is not None:
            raise RuntimeError(f"localnet exited {process.returncode} before {pattern}")
        time.sleep(0.2)
    raise TimeoutError(f"localnet did not print {pattern} within {timeout}s")


def checked_port(port):
    with socket.socket() as sock:
        if sock.connect_ex(("127.0.0.1", port)) == 0:
            raise RuntimeError(f"port {port} is already occupied")


def wallet_balances(transcript, wallet):
    balances = []
    for row in transcript:
        request = json.loads(row["request_body"])
        if (row["status"] == 200 and request["method"] == "getAddressInformation"
                and request["params"].get("address") == wallet):
            balances.append(int(json.loads(row["response_body"])["result"]["balance"]))
    return balances


def stop(process):
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=10)
    return process.returncode


def demo(workdir, rpc_port, control_port, base_port):
    for port in (rpc_port, control_port, *range(base_port, base_port + 17)):
        checked_port(port)
    workdir.mkdir(parents=True, exist_ok=False)
    network_dir = workdir / "network"
    transcript = workdir / "http-transcript.jsonl"
    output = workdir / "localnet.stdout.log"
    command = [sys.executable, "-u", str(REPO / "scripts/localnet-jsonrpc.py"),
               "--demo", "--validators", "1", "--rpc", f"127.0.0.1:{rpc_port}",
               "--control", f"127.0.0.1:{control_port}", "--base-port", str(base_port),
               "--workdir", str(network_dir)]
    environment = {**os.environ, "E03_HTTP_TRANSCRIPT": str(transcript)}
    environment["PYTHONPATH"] = str(REPO / "test/tostester/src") + os.pathsep + environment.get("PYTHONPATH", "")
    with output.open("wb") as log:
        process = subprocess.Popen(command, cwd=REPO, env=environment, stdout=log,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            wallet = wait_for_log(output, r"\[demo\] new wallet address: (\S+)", process, 180).group(1)
            wait_for_log(output, r"\[localnet\] resident; press Ctrl-C to exit\.", process, 120)
            masterchain = rpc(f"127.0.0.1:{rpc_port}", "getMasterchainInfo")
            address_info = rpc(f"127.0.0.1:{rpc_port}", "getAddressInformation", address=wallet)
            (workdir / "external-jsonrpc.json").write_text(json.dumps(
                {"getMasterchainInfo": masterchain, "getAddressInformation": address_info}, indent=2) + "\n")
            replies = [json.loads(row) for row in transcript.read_text().splitlines()]
            balances = wallet_balances(replies, wallet)
            assert len(balances) >= 2 and balances[-1] > balances[0], (
                f"demo wallet did not gain balance: {balances}")
            masterchain_value = json.loads(masterchain["response_body"])
            address_value = json.loads(address_info["response_body"])
            assert masterchain["status"] == 200 and masterchain_value.get("ok") is True
            assert address_info["status"] == 200 and address_value.get("ok") is True
            assert masterchain_value.get("result", {}).get("last", {}).get("seqno", 0) > 0
            assert int(address_value["result"]["balance"]) >= balances[-1]
            result = {"command": command, "wallet": wallet, "balances": balances,
                      "masterchain_seqno": masterchain_value["result"]["last"]["seqno"]}
        finally:
            exit_code = stop(process)
    result["exit_code"] = exit_code
    assert exit_code == 0, f"bounded localnet interrupt exited {exit_code}"
    return result


def toscan(workdir, tosctl, rpc_port, control_port, explorer_port, base_port):
    for port in (rpc_port, control_port, explorer_port, *range(base_port, base_port + 17)):
        checked_port(port)
    workdir.mkdir(parents=True, exist_ok=False)
    output = workdir / "toscan.stdout.log"
    transcript = workdir / "http-transcript.jsonl"
    command = [sys.executable, "-u", str(REPO / "scripts/toscan-explorer-e2e.py"),
               "--workdir", str(workdir / "network"), "--tosctl", str(tosctl),
               "--rpc-port", str(rpc_port), "--control-port", str(control_port),
               "--explorer-port", str(explorer_port), "--base-port", str(base_port)]
    environment = {**os.environ, "E03_HTTP_TRANSCRIPT": str(transcript)}
    environment["PYTHONPATH"] = str(REPO / "test/tostester/src") + os.pathsep + environment.get("PYTHONPATH", "")
    with output.open("wb") as log:
        completed = subprocess.run(command, cwd=REPO, env=environment, stdout=log,
                                   stderr=subprocess.STDOUT, timeout=900)
    assert completed.returncode == 0, f"TOSCAN route exited {completed.returncode}"
    assert "TOSCAN REAL-CHAIN GATE: PASS" in output.read_text(), "TOSCAN did not report its route gate"
    return {"command": command, "exit_code": completed.returncode}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workdir", required=True, type=Path)
    parser.add_argument("--tosctl", type=Path, default=REPO / "tosctl/src/target/debug/tosctl")
    args = parser.parse_args()
    root = args.workdir.resolve()
    root.mkdir(parents=True, exist_ok=False)
    report = {"source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
              "binaries": {name: sha256(path) for name, path in {
                  "validator-engine": REPO / "build/validator-engine/validator-engine",
                  "dht-server": REPO / "build/dht-server/dht-server",
                  "lite-client": REPO / "build/lite-client/lite-client",
                  "tosctl": args.tosctl.resolve(),
              }.items()}}
    try:
        report["demo"] = demo(root / "demo", 19545, 19745, 28500)
        report["toscan"] = toscan(root / "toscan", args.tosctl.resolve(), 19451, 19452, 19453, 26900)
        report["passed"] = True
    except Exception as error:
        report["passed"] = False
        report["failure"] = repr(error)
        raise
    finally:
        (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
