#!/usr/bin/env python3
"""Exercise actual loopback services without contacting any validator or cloud."""
import datetime
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = ROOT / "target/debug"

def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

def call(base, path, token, value=None, run_token=None):
    headers = {"Authorization": "Bearer " + token}
    data = None if value is None else json.dumps(value).encode()
    if data is not None:
        headers["Content-Type"] = "application/json"
    if run_token:
        headers["X-TOS-Run-Token"] = run_token
    req = urllib.request.Request(base + path, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=2) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, None

def ready(base):
    for _ in range(30):
        try:
            with urllib.request.urlopen(base + "/healthz", timeout=0.2):
                return
        except urllib.error.HTTPError:
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("service failed to listen")

with tempfile.TemporaryDirectory(prefix="tos-health-smoke-") as folder:
    directory = pathlib.Path(folder)
    for name in ["edge", "operator", "ingest", "service"]:
        path = directory / name
        path.write_text(name[0] * 64)
        path.chmod(0o600)
    inventory = directory / "inventory.json"
    inventory.write_text(json.dumps({"network_id": "isolated-fixture", "nodes": ["v1"], "scopes": ["node"]}))
    edge_port, query_port = port(), port()
    proc_pid = pathlib.Path("/proc/self").readlink().name
    processes = []
    try:
        processes.append(subprocess.Popen([str(BIN / "health-edge"), "v1", proc_pid, f"127.0.0.1:{edge_port}", str(directory / "edge")], stdout=subprocess.PIPE, stderr=subprocess.PIPE))
        processes.append(subprocess.Popen([str(BIN / "tos-observability"), str(inventory), f"127.0.0.1:{query_port}", str(directory / "operator"), str(directory / "ingest"), str(directory / "service")], stdout=subprocess.PIPE, stderr=subprocess.PIPE))
        edge, query = f"http://127.0.0.1:{edge_port}", f"http://127.0.0.1:{query_port}"
        ready(edge)
        ready(query)
        status, record = call(edge, "/v1/edge/snapshot", "e" * 64)
        if status == 503:
            time.sleep(0.1)
            status, record = call(edge, "/v1/edge/snapshot", "e" * 64)
        assert status == 200, status
        assert record["node_id"] == "v1"
        assert record["quality"]["coverage"] == "partial"
        assert call(query, "/v1/ingest", "s" * 64, record)[0] == 401
        assert call(query, "/v1/ingest", "i" * 64, record)[0] == 200
        now = datetime.datetime.now(datetime.timezone.utc)
        timestamp = lambda dt: dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        status, grant = call(query, "/v1/control/grants", "o" * 64, {"node_ids": ["v1"], "scope_ids": ["node"], "start": timestamp(now - datetime.timedelta(seconds=60)), "end": timestamp(now)})
        assert status == 200
        request = {"run_id": grant["run_id"], "node_id": "v1", "as_of": timestamp(now), "max_age_seconds": 30, "components": ["process"]}
        status, answer = call(query, "/v1/query/node-snapshot", "s" * 64, request, grant["run_token"])
        assert status == 200 and answer["status"] == "ok", answer
        assert answer["data"]["process"]["record"]["source_record_id"] == record["source_record_id"]
        assert call(query, f'/v1/control/grants/{grant["run_id"]}/revoke', "o" * 64, {})[0] == 200
        assert call(query, "/v1/query/node-snapshot", "s" * 64, request, grant["run_token"])[0] == 401
        print("PASS: process sample -> cache -> ingest -> scoped HTTP query -> revoke")
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            try:
                process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
