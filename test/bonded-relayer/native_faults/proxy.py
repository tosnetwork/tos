#!/usr/bin/env python3
"""Bounded loopback RPC fault gate: forward once, then lose sendBoc's reply."""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import http.server
import json
import os
import re
import socket
import subprocess
import threading
import urllib.request
from pathlib import Path


class Gate(http.server.HTTPServer):
    # Serialize forwarding: no unbounded handlers, retries or capture races.
    allow_reuse_address = True

    def __init__(self, args):
        self.args = args
        self.index = max(
            [int(path.name.split(".")[0]) for path in args.out.glob("*.request.json")] + [0]
        )
        self.total = sum(path.stat().st_size for path in args.out.iterdir() if path.is_file())
        self.guard = threading.Lock()
        super().__init__(("127.0.0.1", args.port), Handler)

    def save(self, path, data):
        self.total += len(data)
        if self.total > 128 * 1024 * 1024:
            raise RuntimeError("capture byte bound reached")
        with path.open("xb") as stream:
            stream.write(data)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        self.connection.settimeout(20)
        gate = self.server
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size <= 2 * 1024 * 1024:
            self.send_error(413)
            return
        body = self.rfile.read(size)
        value = json.loads(body)
        if value.get("method") not in ("getConfigAll", "getTransactions", "sendBoc"):
            self.send_error(400)
            return
        with gate.guard:
            gate.index += 1
            if gate.index > 512:
                raise RuntimeError("capture count bound reached")
            stem = gate.args.out / f"{gate.index:05d}"
            gate.save(stem.with_suffix(".request.json"), body)
            request = urllib.request.Request(
                f"http://127.0.0.1:{gate.args.upstream_port}/jsonRPC",
                body,
                {"Content-Type": "application/json"},
            )
            # Disable environment proxies; a transport failure is never retried.
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(request, timeout=15) as response:
                data = response.read(2 * 1024 * 1024 + 1)
            if len(data) > 2 * 1024 * 1024:
                raise RuntimeError("RPC response byte bound")
            gate.save(stem.with_suffix(".response.json"), data)
            if value["method"] == "sendBoc":
                receipt = {
                    "method": "sendBoc",
                    "original_message_sha256": hashlib.sha256(
                        base64.b64decode(value["params"]["boc"], validate=True)
                    ).hexdigest(),
                    "forward_attempts": 1,
                    "response_sha256": hashlib.sha256(data).hexdigest(),
                    "reply_dropped": True,
                    "killed_unit": gate.args.kill_unit,
                }
                if gate.args.kill_unit:
                    subprocess.run(
                        [
                            "systemctl",
                            "--user",
                            "kill",
                            "--kill-who=all",
                            "--signal=SIGKILL",
                            gate.args.kill_unit,
                        ],
                        check=True,
                        timeout=10,
                    )
                gate.save(
                    stem.with_suffix(".fault.json"),
                    (json.dumps(receipt, sort_keys=True) + "\n").encode(),
                )
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--upstream-port", type=int, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--kill-unit")
    args = parser.parse_args()
    if not all(1024 <= value <= 65535 for value in (args.port, args.upstream_port)):
        parser.error("loopback port bound")
    if args.port == args.upstream_port:
        parser.error("proxy must not forward to itself")
    if args.kill_unit and not re.fullmatch(r"br1-operator-[a-z0-9-]+\.service", args.kill_unit):
        parser.error("only an explicit local BR1 operator unit can be killed")
    os.umask(0o077)
    args.out.mkdir(mode=0o700, parents=False, exist_ok=True)
    metadata = args.out.stat()
    if metadata.st_mode & 0o077 or metadata.st_uid != os.geteuid():
        parser.error("capture directory must be owned and private")
    with (args.out / "proxy.lock").open("ab") as owner:
        fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with Gate(args) as server:
            server.serve_forever()


if __name__ == "__main__":
    main()
